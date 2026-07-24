import json
import tempfile
import unittest
from pathlib import Path

import forge


class ResumeSecurityBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.project = Path(self.temp.name) / "project"
        self.project.mkdir()
        (self.project / ".forge" / "runs").mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def config(self, **updates):
        config = forge.DEFAULT_CONFIG.copy()
        config.update(
            {
                "adaptive_orchestration": False,
                "runtime_preflight": False,
            }
        )
        config.update(updates)
        return config

    def write_source(
        self,
        *,
        run_id="source",
        config=None,
        stop_reason="reviewer_continue",
        automatic=True,
        counters=None,
        integrity=True,
        extension_count=0,
        base_budgets=None,
        last_extension_source=None,
    ):
        config = config or self.config()
        effective = forge.ChainBudgets.model_validate(config["chain_budgets"])
        base = base_budgets or effective
        counters = counters or forge.ChainCounters()
        run_dir = self.project / ".forge" / "runs" / run_id
        run_dir.mkdir()
        snapshot = forge._canonical_config_snapshot(config)
        digest = forge.config_hash(snapshot)
        continuation = forge.ContinuationPayload(
            source_run_id=run_id,
            continuation_chain_id="chain",
            next_prompt="Continue the exact validated work.",
            acceptance_criteria=["Checks pass."],
            repository_fingerprint="fingerprint",
            repository_manifest={},
            no_progress_count=0,
            failed_iterations=0,
            chain_worker_calls=counters.worker_calls,
            chain_elapsed_seconds=counters.elapsed_seconds,
            chain_full_check_suites=counters.full_check_suites,
            chain_premium_escalations=counters.premium_escalations,
            chain_child_runs=counters.child_runs,
            chain_codex_calls=counters.codex_calls,
            chain_no_progress_events=counters.no_progress_events,
            config_hash=digest if integrity else None,
            base_chain_budgets=base if integrity else None,
            effective_chain_budgets=effective if integrity else None,
            budget_extension_count=extension_count if integrity else 0,
            last_budget_extension_source_run_id=(
                last_extension_source if integrity else None
            ),
        )
        run_payload = {
            "schema_version": forge.SCHEMA_VERSION,
            "run_id": run_id,
            "goal": "Safe goal",
            "config": config,
        }
        result_payload = {
            "schema_version": forge.SCHEMA_VERSION,
            "run_id": run_id,
            "parent_run_id": None,
            "continuation_chain_id": "chain",
            "goal": "Safe goal",
            "final_status": "needs_continuation",
            "stop_reason_code": stop_reason,
            "automatic_resume_allowed": automatic,
            "continuation": continuation.model_dump(mode="json"),
        }
        if integrity:
            (run_dir / "config.snapshot.json").write_text(
                json.dumps(snapshot), encoding="utf-8"
            )
            integrity_payload = {
                "config_integrity_version": forge.CONFIG_INTEGRITY_VERSION,
                "config_hash": digest,
                "config_snapshot_file": "config.snapshot.json",
                "base_chain_budgets": base.model_dump(mode="json"),
                "effective_chain_budgets": effective.model_dump(mode="json"),
                "budget_extension_count": extension_count,
                "last_budget_extension_source_run_id": last_extension_source,
            }
            run_payload.update(integrity_payload)
            result_payload.update(integrity_payload)
        (run_dir / "run.json").write_text(
            json.dumps(run_payload), encoding="utf-8"
        )
        (run_dir / "result.json").write_text(
            json.dumps(result_payload), encoding="utf-8"
        )
        return run_dir

    def test_tampered_current_config_is_rejected_fail_closed(self):
        run_dir = self.write_source()
        payload = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        payload["config"]["security_profile"] = "strict"
        (run_dir / "run.json").write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(RuntimeError, "canonical snapshot"):
            forge.load_resume_context(self.project, "source")

    def test_canonical_config_snapshot_is_an_exact_deep_json_copy(self):
        config = {
            "nested": {"api_key": "fixture-value", "values": [1, True, None]}
        }
        snapshot = forge._canonical_config_snapshot(config)
        self.assertEqual(snapshot, config)
        self.assertIsNot(snapshot, config)
        self.assertIsNot(snapshot["nested"], config["nested"])

    def test_legacy_config_requires_explicit_resume(self):
        self.write_source(integrity=False)

        with self.assertRaisesRegex(RuntimeError, "cannot be resumed automatically"):
            forge.load_resume_context(
                self.project,
                "source",
                resume_kind="internal_automatic",
            )
        context = forge.load_resume_context(
            self.project,
            "source",
            resume_kind="explicit_human",
        )
        self.assertTrue(context["legacy_config_compatibility"])

    def test_explicit_budget_resume_adds_one_cumulative_nonpremium_tranche(self):
        budget = forge.ChainBudgets(
            max_child_runs=2,
            max_codex_calls=4,
            max_worker_calls=4,
            max_elapsed_seconds=120,
            max_full_check_suites=2,
            max_premium_escalations=1,
            max_no_progress_events=2,
        )
        config = self.config(chain_budgets=budget.model_dump(mode="json"))
        counters = forge.ChainCounters(
            child_runs=2,
            codex_calls=3,
            worker_calls=3,
            elapsed_seconds=60,
            full_check_suites=1,
            premium_escalations=1,
            no_progress_events=1,
        )
        self.write_source(
            config=config,
            stop_reason="chain_budget_exhausted",
            automatic=False,
            counters=counters,
        )

        context = forge.load_resume_context(
            self.project,
            "source",
            resume_kind="explicit_human",
        )
        effective = forge.ChainBudgets.model_validate(
            context["effective_chain_budgets"]
        )
        inherited = forge.ContinuationPayload.model_validate(
            context["continuation"]
        )
        self.assertEqual(effective.max_child_runs, 4)
        self.assertEqual(effective.max_worker_calls, 8)
        self.assertEqual(effective.max_elapsed_seconds, 240)
        self.assertEqual(effective.max_premium_escalations, 1)
        self.assertEqual(context["budget_extension_count"], 1)
        self.assertEqual(inherited.chain_child_runs, 2)
        self.assertEqual(inherited.chain_premium_escalations, 1)

        with self.assertRaisesRegex(RuntimeError, "cannot extend"):
            forge.load_resume_context(
                self.project,
                "source",
                resume_kind="internal_automatic",
            )

    def test_persisted_budget_tranche_algebra_must_match_extension_count(self):
        base = forge.ChainBudgets(
            max_child_runs=2,
            max_codex_calls=4,
            max_worker_calls=4,
            max_elapsed_seconds=120,
            max_full_check_suites=2,
            max_premium_escalations=1,
            max_no_progress_events=2,
        )
        invalid_effective = base.model_copy(
            update={"max_worker_calls": 5}
        )
        config = self.config(
            chain_budgets=invalid_effective.model_dump(mode="json")
        )
        self.write_source(
            config=config,
            extension_count=1,
            base_budgets=base,
            last_extension_source="prior-run",
        )

        with self.assertRaisesRegex(RuntimeError, "tranche algebra"):
            forge.load_resume_context(
                self.project,
                "source",
                resume_kind="explicit_human",
            )

    def test_second_explicit_tranche_is_cumulative_and_keeps_premium_ceiling(self):
        base = forge.ChainBudgets(
            max_child_runs=2,
            max_codex_calls=4,
            max_worker_calls=4,
            max_elapsed_seconds=120,
            max_full_check_suites=2,
            max_premium_escalations=1,
            max_no_progress_events=2,
        )
        effective = forge.ChainBudgets(
            max_child_runs=4,
            max_codex_calls=8,
            max_worker_calls=8,
            max_elapsed_seconds=240,
            max_full_check_suites=4,
            max_premium_escalations=1,
            max_no_progress_events=4,
        )
        config = self.config(
            chain_budgets=effective.model_dump(mode="json")
        )
        self.write_source(
            config=config,
            stop_reason="chain_budget_exhausted",
            automatic=False,
            counters=forge.ChainCounters(child_runs=4),
            extension_count=1,
            base_budgets=base,
            last_extension_source="prior-run",
        )

        context = forge.load_resume_context(
            self.project,
            "source",
            resume_kind="explicit_human",
        )
        extended = forge.ChainBudgets.model_validate(
            context["effective_chain_budgets"]
        )
        inherited = forge.ContinuationPayload.model_validate(
            context["continuation"]
        )
        self.assertEqual(extended.max_child_runs, 6)
        self.assertEqual(extended.max_worker_calls, 12)
        self.assertEqual(extended.max_premium_escalations, 1)
        self.assertEqual(context["budget_extension_count"], 2)
        self.assertEqual(
            inherited.last_budget_extension_source_run_id,
            "source",
        )

    def test_unattended_resume_uses_stricter_supervisor_envelope(self):
        source = self.config(
            security_profile="balanced",
            sandbox_checks="auto",
            claude_outer_srt_on_wsl=False,
            claude_tools="Bash,Read,Edit",
            check_network_domains=["source.example", "shared.example"],
            runtime_preflight=False,
            adaptive_auto_supervisor=False,
            check_cache_enabled=True,
            mode="legacy-balanced",
        )
        supervisor = self.config(
            security_profile="strict",
            sandbox_checks="required",
            claude_outer_srt_on_wsl=True,
            claude_tools="Bash,Read",
            check_network_domains=["shared.example", "supervisor.example"],
            mode="economy-safe-strict",
            adaptive_orchestration=True,
            adaptive_auto_supervisor=True,
        )
        effective, changed = forge.enforce_unattended_resume_config(
            source,
            supervisor,
            in_wsl=True,
        )
        self.assertEqual(effective["security_profile"], "strict")
        self.assertEqual(effective["sandbox_checks"], "required")
        self.assertTrue(effective["claude_outer_srt_on_wsl"])
        self.assertEqual(effective["claude_tools"], "Bash,Read")
        self.assertEqual(effective["check_network_domains"], ["shared.example"])
        self.assertTrue(effective["runtime_preflight"])
        self.assertTrue(effective["adaptive_orchestration"])
        self.assertTrue(effective["adaptive_auto_supervisor"])
        self.assertFalse(effective["check_cache_enabled"])
        self.assertEqual(effective["mode"], "economy-safe-strict")
        self.assertIn("security_profile", changed)

    def test_eligibility_can_apply_the_same_trusted_supervisor_envelope(self):
        self.write_source()
        supervisor = self.config(
            security_profile="strict",
            sandbox_checks="required",
            claude_outer_srt_on_wsl=True,
            mode="economy-safe-strict",
            adaptive_orchestration=True,
            adaptive_auto_supervisor=True,
        )
        result = forge.resume_eligibility(
            self.project,
            "source",
            supervisor_config=supervisor,
            in_wsl=True,
        )
        self.assertTrue(result["eligible"])
        self.assertTrue(result["supervisor_config_enforced"])
        self.assertEqual(result["effective_security_profile"], "strict")
        self.assertIn("security_profile", result["safety_overrides"])

    def test_wsl_unattended_rejects_missing_strict_outer_srt_policy(self):
        source = self.config()
        supervisor = self.config(
            security_profile="strict",
            claude_outer_srt_on_wsl=False,
        )
        with self.assertRaisesRegex(RuntimeError, "outer_srt"):
            forge.enforce_unattended_resume_config(
                source,
                supervisor,
                in_wsl=True,
            )


if __name__ == "__main__":
    unittest.main()
