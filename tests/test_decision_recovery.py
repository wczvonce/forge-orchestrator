from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import forge
import forge_adaptive as adaptive


REAL_RECOVERY_PROJECT = os.environ.get(
    "FORGE_TEST_REAL_DECISION_RECOVERY_PROJECT", ""
)
REAL_RECOVERY_RUN_ID = os.environ.get(
    "FORGE_TEST_REAL_DECISION_RECOVERY_RUN_ID", ""
)
REAL_RECOVERY_SHA = os.environ.get(
    "FORGE_TEST_REAL_DECISION_RECOVERY_SHA256", ""
)
REAL_BUDGET_NORMALIZATION_PROJECT = os.environ.get(
    "FORGE_TEST_REAL_BUDGET_NORMALIZATION_PROJECT", ""
)
REAL_BUDGET_NORMALIZATION_RUN_ID = os.environ.get(
    "FORGE_TEST_REAL_BUDGET_NORMALIZATION_RUN_ID", ""
)


class DecisionNormalizationTests(unittest.TestCase):
    def test_native_false_reason_is_the_only_normalized_field(self) -> None:
        raw = {
            "schema_version": 4,
            "status": "continue",
            "decision_kind": "repair_packet",
            "assessment": "Repair.",
            "active_packet_id": "WP-01A",
            "next_prompt": "Repair exactly this.",
            "acceptance_criteria": ["The repair is verified."],
            "approve_check_contract_drift": False,
            "check_contract_approval_reason": "No drift approval is requested.",
        }
        normalized = forge.normalize_codex_decision_payload(raw)
        self.assertEqual(
            normalized["check_contract_approval_reason"],
            "",
        )
        self.assertEqual(
            raw["check_contract_approval_reason"],
            "No drift approval is requested.",
        )
        self.assertFalse(forge.Decision.model_validate(normalized).approve_check_contract_drift)

    def test_normalizer_never_coerces_or_weakens_true_approval(self) -> None:
        with self.assertRaises(ValueError):
            forge.normalize_codex_decision_payload(
                {"approve_check_contract_drift": "false"}
            )
        raw_true = {
            "approve_check_contract_drift": True,
            "check_contract_approval_reason": "",
        }
        self.assertEqual(
            forge.normalize_codex_decision_payload(raw_true),
            raw_true,
        )

    def test_normalization_cannot_mask_an_additional_validation_error(self) -> None:
        raw = {
            "schema_version": 4,
            "status": "continue",
            "decision_kind": "repair_packet",
            "assessment": "Repair.",
            "active_packet_id": "WP-01A",
            "next_prompt": "Repair exactly this.",
            "acceptance_criteria": ["The repair is verified."],
            "approve_check_contract_drift": False,
            "check_contract_approval_reason": "No approval.",
            "unexpected_security_field": True,
        }
        normalized = forge.normalize_codex_decision_payload(raw)
        with self.assertRaises(Exception):
            forge.Decision.model_validate(normalized)


class PostWorkerDecisionRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.source_id = "failed-source"
        self.parent_id = "parent-source"
        self.chain_id = "chain-source"
        self.goal = "Complete the bounded mobile application repair."
        self.expected_sha = self._write_fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_fixture(self) -> str:
        forge.ensure_git_repo(self.project)
        (self.project / "app.txt").write_text("stable\n", encoding="utf-8")
        identity = adaptive.stable_project_identity(self.project)
        config = forge.DEFAULT_CONFIG.copy()
        config.update(
            {
                "adaptive_orchestration": True,
                "runtime_preflight": False,
                "auto_detect_checks": False,
                "check_definitions": [],
                "checks": [],
                "max_packet_attempts": 3,
            }
        )
        contract = forge.ensure_check_contract(self.project, config)
        check_definition = contract.check_definitions[0]
        source = adaptive.WorkPacket(
            packet_id="WP-01A",
            title="Exhausted repair",
            objective="Repair the exact issue.",
            acceptance_criteria=["The issue is repaired."],
            status="in_progress",
            risk="medium",
            check_tier=check_definition.tier,
            expected_paths=["app.txt"],
            forbidden_scope=["secrets/**"],
            attempts=4,
            final_review_recovery_used=True,
        )
        downstream = adaptive.WorkPacket(
            packet_id="WP-02",
            title="Downstream verification",
            objective="Verify downstream behavior.",
            dependencies=["WP-01A", "WP-01A"],
            acceptance_criteria=["Downstream behavior is verified."],
            status="pending",
            check_tier=check_definition.tier,
        )
        plan = adaptive.ProjectPlan(
            plan_id="plan-source",
            project_id=identity["project_id"],
            goal_hash=adaptive.sha256_text(self.goal),
            spec_hash=adaptive.sha256_text(""),
            created_at="2026-07-24T00:00:00+00:00",
            updated_at="2026-07-24T00:00:00+00:00",
            status="active",
            active_packet_id=source.packet_id,
            work_packets=[source, downstream],
            check_contract_hash=contract.contract_hash,
        )
        adaptive.save_plan(self.project, plan)
        plan = adaptive.ProjectPlan.model_validate_json(
            (self.project / ".forge" / "project-plan.json").read_text(
                encoding="utf-8"
            )
        )
        plan_digest = adaptive.plan_hash(plan)
        snapshot = forge._canonical_config_snapshot(config)
        snapshot_hash = adaptive.config_hash(snapshot)
        budgets = adaptive.ChainBudgets.model_validate(
            snapshot["chain_budgets"]
        )
        fingerprint = forge.repo_fingerprint(self.project)
        manifest = forge.repo_manifest(self.project)
        check = forge.CheckResult(
            command=check_definition.command,
            exit_code=0,
            output="ok",
            check_id=check_definition.check_id,
            tier=check_definition.tier,
            check_contract_hash=contract.contract_hash,
        )
        previous_decision = forge.Decision(
            status="continue",
            decision_kind="repair_packet",
            assessment="One bounded repair remains.",
            active_packet_id="WP-01A",
            next_prompt="Repair the exact issue.",
            acceptance_criteria=["The issue is repaired."],
            recommended_worker_profile="standard",
            recommended_review_profile="final_review",
            check_tier=check_definition.tier,
            check_ids=[check_definition.check_id],
        )
        raw_decision = previous_decision.model_dump(mode="json")
        raw_decision.update(
            {
                "assessment": "A precise follow-up repair is required.",
                "next_prompt": "Perform only the precise follow-up repair.",
                "acceptance_criteria": [
                    "The precise follow-up repair is verified."
                ],
                "recommended_worker_max_turns": 2,
                "routing_reason": "Use the bounded standard route.",
                "plan_patch": {
                    "add_packets": [],
                    "update_packets": [
                        {
                            "packet_id": "WP-01A",
                            "status": None,
                            "objective": None,
                            "context": None,
                            "dependencies": None,
                            "acceptance_criteria": None,
                            "difficulty": None,
                            "risk": None,
                            "recommended_worker_profile": None,
                            "recommended_review_profile": None,
                            "check_tier": None,
                            "max_worker_turns": None,
                            "expected_paths": None,
                            "forbidden_scope": None,
                            "attempts_increment": 1,
                            "final_review_recovery_authorized": None,
                            "final_review_recovery_used": None,
                            "last_fingerprint": None,
                            "last_failure_signature": None,
                            "closes_milestone": None,
                            "requires_fresh_release_check": None,
                            "justification": "Record the exhausted source attempt.",
                        }
                    ],
                    "active_packet_id": "WP-01A",
                    "append_milestones": [],
                    "append_release_gates": [],
                    "append_architectural_decisions": [],
                    "append_safe_assumptions": [],
                    "append_risks": [],
                    "explanation": "Keep the repair bounded.",
                },
                "approve_check_contract_drift": False,
                "check_contract_approval_reason": (
                    "The existing contract is sufficient; no approval is needed."
                ),
            }
        )
        raw_text = json.dumps(
            raw_decision,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        raw_sha = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        error = (
            "Codex vrátil neplatné rozhodnutie:\n"
            + forge.truncate(forge.redact_text(raw_text), 5000)
        )

        runs = self.project / ".forge" / "runs"
        parent_dir = runs / self.parent_id
        source_dir = runs / self.source_id
        logs = source_dir / "logs"
        logs.mkdir(parents=True)
        parent_dir.mkdir(parents=True)
        integrity = {
            "config_integrity_version": forge.CONFIG_INTEGRITY_VERSION,
            "config_hash": snapshot_hash,
            "config_snapshot_file": "config.snapshot.json",
            "base_chain_budgets": budgets.model_dump(mode="json"),
            "effective_chain_budgets": budgets.model_dump(mode="json"),
            "budget_extension_count": 0,
            "last_budget_extension_source_run_id": None,
        }
        parent_continuation = forge.ContinuationPayload(
            source_run_id=self.parent_id,
            continuation_chain_id=self.chain_id,
            next_prompt="Repair the exact issue.",
            acceptance_criteria=["The issue is repaired."],
            last_check_results=[check],
            repository_fingerprint=fingerprint,
            repository_manifest=manifest,
            chain_worker_calls=2,
            chain_elapsed_seconds=100.0,
            chain_full_check_suites=1,
            project_id=identity["project_id"],
            plan_id=plan.plan_id,
            plan_hash=plan_digest,
            active_packet_id="WP-01A",
            chain_child_runs=1,
            chain_codex_calls=3,
            check_contract_hash=contract.contract_hash,
            config_hash=snapshot_hash,
            base_chain_budgets=budgets,
            effective_chain_budgets=budgets,
        )
        forge.save_json(
            parent_dir / "run.json",
            {
                "schema_version": 4,
                "run_id": self.parent_id,
                "parent_run_id": None,
                "continuation_chain_id": self.chain_id,
                "goal": self.goal,
            },
        )
        forge.save_json(
            parent_dir / "result.json",
            {
                "schema_version": 4,
                "run_id": self.parent_id,
                "parent_run_id": None,
                "continuation_chain_id": self.chain_id,
                "goal": self.goal,
                "final_status": "needs_continuation",
                "stop_reason_code": "reviewer_continue",
                "automatic_resume_allowed": True,
                "continuation": parent_continuation.model_dump(mode="json"),
            },
        )
        forge.save_json(source_dir / "config.snapshot.json", snapshot)
        source_run = {
            "schema_version": 4,
            "run_id": self.source_id,
            "parent_run_id": self.parent_id,
            "continuation_chain_id": self.chain_id,
            "goal": self.goal,
            "config": snapshot,
            "project_id": identity["project_id"],
            "plan_id": plan.plan_id,
            **integrity,
        }
        forge.save_json(source_dir / "run.json", source_run)
        adaptive.atomic_json(
            source_dir / "project-plan.result.json",
            plan.model_dump(mode="json"),
        )
        adaptive.atomic_json(
            source_dir / "check-contract.snapshot.json",
            contract.model_dump(mode="json"),
        )
        forge.save_json(
            logs / "01-decision-raw.json",
            previous_decision.model_dump(mode="json"),
        )
        forge.save_json(
            logs / "01-decision.json",
            previous_decision.model_dump(mode="json"),
        )
        forge.save_json(
            logs / "01-worker.json",
            forge.WorkerResult(
                exit_code=0,
                summary="A valid worker completed.",
                raw_output="ok",
                duration_seconds=1.0,
                model="sonnet",
                effort="high",
                valid_worker_outcome=True,
            ),
        )
        forge.save_json(logs / "01-checks.json", [check.model_dump(mode="json")])
        for name in (
            "01-post-worker-evidence-index.json",
            "02-evidence-index.json",
        ):
            forge.save_json(
                logs / name,
                {"repository_fingerprint": fingerprint},
            )
        forge.save_json(logs / "02-codex-usage.json", {"model": "review"})
        (logs / "02-decision-raw.json").write_text(
            raw_text,
            encoding="utf-8",
        )
        source_result = {
            "schema_version": 4,
            "run_id": self.source_id,
            "parent_run_id": self.parent_id,
            "continuation_chain_id": self.chain_id,
            "run_directory": str(source_dir),
            "goal": self.goal,
            "final_status": "failed",
            "stop_reason_code": "technical_failure",
            "automatic_resume_allowed": False,
            "continuation": None,
            "final_decision": previous_decision.model_dump(mode="json"),
            "active_packet_id": "WP-01A",
            "checks": [check.model_dump(mode="json")],
            "checks_passed": True,
            "last_check_tier": check_definition.tier,
            "error": error,
            "final_message": error,
            "repository_fingerprint": fingerprint,
            "project_id": identity["project_id"],
            "plan_id": plan.plan_id,
            "plan_hash": plan_digest,
            "check_contract_hash": contract.contract_hash,
            "chain_child_runs": 2,
            "chain_codex_calls": 5,
            "chain_worker_calls": 3,
            "chain_elapsed_seconds": 120.0,
            "chain_full_check_suites": 1,
            "chain_premium_escalations": 0,
            "chain_no_progress_events": 0,
            "no_progress_count": 0,
            "failed_iterations": 0,
            "repeated_failure_count": 0,
            "chain_model_fallbacks": 0,
            "unavailable_models": {},
            "premium_claude_escalations_used": 0,
            "run_premium_claude_escalations_used": 0,
            "last_failure_signature": None,
            "last_release_check_run_id": None,
            **integrity,
        }
        forge.save_json(source_dir / "result.json", source_result)
        forge.save_json(
            source_dir / "telemetry.json",
            {
                "schema_version": 4,
                "run_id": self.source_id,
                "continuation_chain_id": self.chain_id,
                "parent_run_id": self.parent_id,
                "final_status": "failed",
                "child_run_index": 2,
                "chain_elapsed_seconds": 120.0,
                "budget_extension_count": 0,
                "chain_model_fallbacks": 0,
                "unavailable_models": {},
                "premium_escalations": 0,
            },
        )
        return raw_sha

    def load_context(self) -> dict:
        return forge.load_resume_context(
            self.project,
            self.source_id,
            resume_kind="explicit_human",
            authorize_packet_recovery=False,
            expected_decision_recovery_sha256=self.expected_sha,
        )

    def source_tree_hashes(self) -> dict[str, str]:
        source = self.project / ".forge" / "runs" / self.source_id
        return {
            path.relative_to(source).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(source.rglob("*"))
            if path.is_file() and not path.is_symlink()
        }

    def test_read_only_eligibility_and_one_shot_transform(self) -> None:
        plan_path = self.project / ".forge" / "project-plan.json"
        before = plan_path.read_bytes()
        source_before = self.source_tree_hashes()
        config = forge.load_config(
            Path(forge.__file__).with_name("forge.strict.config.json")
        )
        verdict = forge.resume_eligibility(
            self.project,
            self.source_id,
            supervisor_config=config,
            in_wsl=False,
            expected_decision_recovery_sha256=self.expected_sha,
        )
        self.assertTrue(verdict["eligible"], verdict)
        self.assertEqual(
            verdict["action"],
            forge.POST_WORKER_DECISION_RECOVERY_ACTION,
        )
        self.assertEqual(plan_path.read_bytes(), before)
        self.assertEqual(self.source_tree_hashes(), source_before)

        context = self.load_context()
        continuation = context["continuation"]
        self.assertEqual(continuation["chain_child_runs"], 2)
        self.assertEqual(continuation["chain_codex_calls"], 5)
        self.assertEqual(continuation["chain_worker_calls"], 3)
        self.assertEqual(continuation["chain_premium_escalations"], 0)
        self.assertEqual(continuation["chain_model_fallbacks"], 0)
        self.assertEqual(continuation["unavailable_models"], {})
        self.assertEqual(
            continuation["base_chain_budgets"],
            continuation["effective_chain_budgets"],
        )
        source_plan = adaptive.ProjectPlan.model_validate_json(
            plan_path.read_text(encoding="utf-8")
        )
        transformed, runtime_decision = forge.apply_post_worker_decision_recovery_plan(
            source_plan,
            context["post_worker_decision_recovery"],
            context["config"],
        )
        self.assertIsNone(runtime_decision.plan_patch)
        old = next(p for p in transformed.work_packets if p.packet_id == "WP-01A")
        new = next(
            p
            for p in transformed.work_packets
            if p.packet_id
            == context["post_worker_decision_recovery"]["replacement_packet_id"]
        )
        downstream = next(p for p in transformed.work_packets if p.packet_id == "WP-02")
        self.assertEqual((old.status, old.attempts), ("superseded", 4))
        self.assertTrue(old.final_review_recovery_used)
        self.assertEqual(new.attempts, 0)
        self.assertFalse(new.final_review_recovery_authorized)
        self.assertFalse(new.final_review_recovery_used)
        self.assertEqual(downstream.dependencies, [new.packet_id])
        consumed, recovery_attempt = adaptive.begin_packet_attempt(
            transformed,
            new.packet_id,
            context["config"],
        )
        self.assertFalse(recovery_attempt)
        consumed_new = next(
            p for p in consumed.work_packets if p.packet_id == new.packet_id
        )
        self.assertEqual(consumed_new.attempts, 1)
        self.assertFalse(consumed_new.final_review_recovery_used)
        self.assertFalse(
            adaptive.packet_attempt_budget_exhausted(
                consumed_new,
                context["config"],
            )
        )
        reauthorized, authorized = adaptive.authorize_final_review_recovery(
            consumed,
            new.packet_id,
            context["config"],
        )
        self.assertFalse(authorized)
        self.assertEqual(
            adaptive.plan_hash(reauthorized),
            adaptive.plan_hash(consumed),
        )

    def test_direct_internal_wrong_sha_and_second_raw_are_rejected(self) -> None:
        for resume_kind in ("direct_manual", "internal_automatic"):
            with self.subTest(resume_kind=resume_kind):
                with self.assertRaisesRegex(RuntimeError, "explicit human"):
                    forge.load_resume_context(
                        self.project,
                        self.source_id,
                        resume_kind=resume_kind,
                        expected_decision_recovery_sha256=self.expected_sha,
                    )
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            forge.load_resume_context(
                self.project,
                self.source_id,
                resume_kind="explicit_human",
                expected_decision_recovery_sha256="b" * 64,
            )
        logs = (
            self.project
            / ".forge"
            / "runs"
            / self.source_id
            / "logs"
        )
        (logs / "03-decision-raw.json").write_bytes(
            (logs / "02-decision-raw.json").read_bytes()
        )
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            self.load_context()

    def test_repo_plan_contract_and_config_drift_fail_closed(self) -> None:
        plan_path = self.project / ".forge" / "project-plan.json"
        contract_path = self.project / ".forge" / "check-contract.json"
        config_path = (
            self.project
            / ".forge"
            / "runs"
            / self.source_id
            / "config.snapshot.json"
        )
        originals = {
            plan_path: plan_path.read_bytes(),
            contract_path: contract_path.read_bytes(),
            config_path: config_path.read_bytes(),
        }

        app_path = self.project / "app.txt"
        app_stat = app_path.stat()
        app_path.write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "fingerprint changed"):
            self.load_context()
        app_path.write_text("stable\n", encoding="utf-8")
        os.utime(
            app_path,
            ns=(app_stat.st_atime_ns, app_stat.st_mtime_ns),
        )

        plan = adaptive.ProjectPlan.model_validate_json(
            plan_path.read_text(encoding="utf-8")
        )
        plan.work_packets[0].title = "tampered"
        adaptive.atomic_json(plan_path, plan.model_dump(mode="json"))
        with self.assertRaisesRegex(RuntimeError, "neither the exact failed"):
            self.load_context()
        plan_path.write_bytes(originals[plan_path])

        contract_path.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "snapshot is invalid"):
            self.load_context()
        contract_path.write_bytes(originals[contract_path])

        config_payload = json.loads(config_path.read_text(encoding="utf-8"))
        config_payload["max_iterations"] = 9
        config_path.write_text(json.dumps(config_payload), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "differs from its canonical"):
            self.load_context()
        config_path.write_bytes(originals[config_path])
        self.assertTrue(self.load_context()["post_worker_decision_recovery_eligible"])

    def test_packet_cap_long_source_id_and_project_lock_fail_closed(self) -> None:
        context = self.load_context()
        plan_path = self.project / ".forge" / "project-plan.json"
        source_plan = adaptive.ProjectPlan.model_validate_json(
            plan_path.read_text(encoding="utf-8")
        )
        for index in range(10):
            source_plan.work_packets.append(
                adaptive.WorkPacket(
                    packet_id=f"extra-{index}",
                    title=f"Extra {index}",
                    objective="Remain pending.",
                    acceptance_criteria=["The packet remains bounded."],
                )
            )
        source_plan = adaptive.ProjectPlan.model_validate(
            source_plan.model_dump(mode="json")
        )
        recovery = dict(context["post_worker_decision_recovery"])
        recovery["source_plan_hash"] = adaptive.plan_hash(source_plan)
        with self.assertRaisesRegex(RuntimeError, "packet limit"):
            forge.apply_post_worker_decision_recovery_plan(
                source_plan,
                recovery,
                context["config"],
            )
        packet_id = forge._decision_recovery_packet_id(
            "A" * 80,
            self.source_id,
            self.expected_sha,
        )
        self.assertLessEqual(len(packet_id), 80)
        self.assertRegex(packet_id, r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")

        before = plan_path.read_bytes()
        supervisor = forge.load_config(
            Path(forge.__file__).with_name("forge.strict.config.json")
        )
        with forge.project_run_lock(
            self.project,
            create_forge_directory=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "already active"):
                forge.resume_forge(
                    self.project,
                    self.source_id,
                    resume_kind="explicit_human",
                    supervisor_config=supervisor,
                    expected_decision_recovery_sha256=self.expected_sha,
                )
        self.assertEqual(plan_path.read_bytes(), before)

    def test_journal_allows_only_source_or_exact_target_state(self) -> None:
        context = self.load_context()
        recovery = context["post_worker_decision_recovery"]
        plan_path = self.project / ".forge" / "project-plan.json"
        source_plan = adaptive.ProjectPlan.model_validate_json(
            plan_path.read_text(encoding="utf-8")
        )
        transformed, _ = forge.apply_post_worker_decision_recovery_plan(
            source_plan,
            recovery,
            context["config"],
        )
        target = forge._prepare_recovery_plan_for_persistence(transformed)
        journal = {
            "schema_version": forge.SCHEMA_VERSION,
            "action": forge.POST_WORKER_DECISION_RECOVERY_ACTION,
            "source_run_id": self.source_id,
            "source_packet_id": recovery["source_packet_id"],
            "replacement_packet_id": recovery["replacement_packet_id"],
            "raw_decision_sha256": self.expected_sha,
            "source_plan_hash": recovery["source_plan_hash"],
            "source_contract_hash": recovery["source_contract_hash"],
            "source_repository_fingerprint": recovery[
                "source_repository_fingerprint"
            ],
            "source_config_hash": context["source_config_hash"],
            "prepared_by_run_id": "orphan-preparation",
            "created_at": "2026-07-25T00:00:00+00:00",
            "phase": "prepared",
            "child_run_id": None,
            "target_plan_hash": adaptive.plan_hash(target),
            "target_plan": target.model_dump(mode="json"),
        }
        adaptive.atomic_json(
            forge._decision_recovery_journal_path(
                self.project,
                self.source_id,
            ),
            journal,
        )
        intent = self.load_context()
        self.assertEqual(
            intent["post_worker_decision_recovery"]["journal_state"],
            "intent_only",
        )
        adaptive.atomic_json(
            plan_path,
            target.model_dump(mode="json"),
        )
        applied = self.load_context()
        self.assertEqual(
            applied["post_worker_decision_recovery"]["journal_state"],
            "target_applied",
        )
        self.assertEqual(
            applied["continuation"]["plan_hash"],
            adaptive.plan_hash(target),
        )
        tampered = target.model_copy(deep=True)
        replacement = next(
            p
            for p in tampered.work_packets
            if p.packet_id == recovery["replacement_packet_id"]
        )
        replacement.objective += " tampered"
        adaptive.atomic_json(plan_path, tampered.model_dump(mode="json"))
        with self.assertRaisesRegex(RuntimeError, "differs from both states"):
            self.load_context()
        adaptive.atomic_json(plan_path, target.model_dump(mode="json"))
        forge._mark_decision_recovery_child_started(
            self.project,
            self.source_id,
            "started-child",
        )
        with self.assertRaisesRegex(RuntimeError, "already started"):
            self.load_context()

    def test_sha_latest_and_existing_child_fail_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "exact source run ID"):
            forge.load_resume_context(
                self.project,
                "latest",
                resume_kind="explicit_human",
                expected_decision_recovery_sha256=self.expected_sha,
            )
        with self.assertRaisesRegex(RuntimeError, "audited lowercase SHA-256"):
            forge.load_resume_context(
                self.project,
                self.source_id,
                resume_kind="explicit_human",
                expected_decision_recovery_sha256="A" * 64,
            )
        child = self.project / ".forge" / "runs" / "existing-child"
        child.mkdir()
        forge.save_json(
            child / "run.json",
            {
                "run_id": "existing-child",
                "parent_run_id": self.source_id,
            },
        )
        with self.assertRaisesRegex(RuntimeError, "one-shot"):
            self.load_context()


class RecoveryAttemptBudgetNormalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.failed_id = "failed-source"
        self.failed_parent_id = "parent-source"
        self.child_id = "legacy-recovery-child"
        self.chain_id = "chain-source"
        self.goal = "Complete the bounded mobile application repair."

        fixture = object.__new__(PostWorkerDecisionRecoveryTests)
        fixture.project = self.project
        fixture.source_id = self.failed_id
        fixture.parent_id = self.failed_parent_id
        fixture.chain_id = self.chain_id
        fixture.goal = self.goal
        self.expected_sha = fixture._write_fixture()
        self._write_legacy_recovery_child()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _post_worker_context(self) -> dict:
        return forge.load_resume_context(
            self.project,
            self.failed_id,
            resume_kind="explicit_human",
            authorize_packet_recovery=False,
            expected_decision_recovery_sha256=self.expected_sha,
        )

    def _write_legacy_recovery_child(self) -> None:
        context = self._post_worker_context()
        source_plan = adaptive.ProjectPlan.model_validate_json(
            (self.project / ".forge" / "project-plan.json").read_text(
                encoding="utf-8"
            )
        )
        transformed, initial_decision = (
            forge.apply_post_worker_decision_recovery_plan(
                source_plan,
                context["post_worker_decision_recovery"],
                context["config"],
            )
        )
        replacement_id = context["post_worker_decision_recovery"][
            "replacement_packet_id"
        ]
        maximum = int(context["config"]["max_packet_attempts"])
        replacement = next(
            packet
            for packet in transformed.work_packets
            if packet.packet_id == replacement_id
        )
        replacement.attempts = maximum
        replacement.final_review_recovery_authorized = True
        replacement.final_review_recovery_used = False
        legacy_target = forge._prepare_recovery_plan_for_persistence(
            adaptive.ProjectPlan.model_validate(
                transformed.model_dump(mode="json")
            )
        )
        legacy_target_hash = adaptive.plan_hash(legacy_target)

        legacy_journal = {
            "schema_version": forge.SCHEMA_VERSION,
            "action": forge.POST_WORKER_DECISION_RECOVERY_ACTION,
            "source_run_id": self.failed_id,
            "source_packet_id": context[
                "post_worker_decision_recovery"
            ]["source_packet_id"],
            "replacement_packet_id": replacement_id,
            "raw_decision_sha256": self.expected_sha,
            "source_plan_hash": context[
                "post_worker_decision_recovery"
            ]["source_plan_hash"],
            "source_contract_hash": context[
                "post_worker_decision_recovery"
            ]["source_contract_hash"],
            "source_repository_fingerprint": context[
                "post_worker_decision_recovery"
            ]["source_repository_fingerprint"],
            "source_config_hash": context["source_config_hash"],
            "prepared_by_run_id": self.child_id,
            "created_at": "2026-07-25T01:00:00+00:00",
            "phase": "child_started",
            "child_run_id": self.child_id,
            "target_plan_hash": legacy_target_hash,
            "target_plan": legacy_target.model_dump(mode="json"),
        }
        adaptive.atomic_json(
            forge._decision_recovery_journal_path(
                self.project, self.failed_id
            ),
            legacy_journal,
        )

        consumed, recovery_attempt = adaptive.begin_packet_attempt(
            legacy_target,
            replacement_id,
            context["config"],
        )
        self.assertTrue(recovery_attempt)
        pre_worker_plan = adaptive.ProjectPlan.model_validate(
            consumed.model_dump(mode="json")
        )
        consumed_packet = next(
            packet
            for packet in consumed.work_packets
            if packet.packet_id == replacement_id
        )
        fingerprint = forge.repo_fingerprint(self.project)
        manifest = forge.repo_manifest(self.project)
        consumed_packet.last_fingerprint = fingerprint
        consumed_packet.context = (
            "A valid worker made measurable progress and green checks passed."
        )
        consumed = adaptive.ProjectPlan.model_validate(
            consumed.model_dump(mode="json")
        )
        consumed_hash = adaptive.plan_hash(consumed)
        adaptive.atomic_json(
            self.project / ".forge" / "project-plan.json",
            consumed.model_dump(mode="json"),
        )

        config = forge._canonical_config_snapshot(context["config"])
        config_hash = adaptive.config_hash(config)
        self.assertEqual(config_hash, context["source_config_hash"])
        budgets = adaptive.ChainBudgets.model_validate(
            config["chain_budgets"]
        )
        contract = forge.CheckContract.model_validate_json(
            (self.project / ".forge" / "check-contract.json").read_text(
                encoding="utf-8"
            )
        )
        check = context["continuation"]["last_check_results"][0]
        final_decision = forge.Decision(
            status="continue",
            decision_kind="repair_packet",
            assessment="One precise bounded repair remains.",
            active_packet_id=replacement_id,
            next_prompt="Perform the exact remaining bounded repair.",
            acceptance_criteria=["The remaining repair is verified."],
            risks=["Do not broaden scope."],
            recommended_worker_profile="standard",
            recommended_review_profile="final_review",
            check_tier=check["tier"],
            check_ids=[check["check_id"]],
        )
        continuation = forge.ContinuationPayload(
            source_run_id=self.child_id,
            continuation_chain_id=self.chain_id,
            next_prompt=final_decision.next_prompt or "",
            acceptance_criteria=final_decision.acceptance_criteria,
            risks=final_decision.risks,
            last_check_results=[forge.CheckResult.model_validate(check)],
            repository_fingerprint=fingerprint,
            repository_manifest=manifest,
            no_progress_count=0,
            failed_iterations=0,
            chain_worker_calls=4,
            chain_elapsed_seconds=130.0,
            chain_full_check_suites=1,
            chain_premium_escalations=0,
            project_id=consumed.project_id,
            plan_id=consumed.plan_id,
            plan_hash=consumed_hash,
            active_packet_id=replacement_id,
            chain_child_runs=3,
            chain_codex_calls=6,
            chain_no_progress_events=0,
            unavailable_models={},
            chain_model_fallbacks=0,
            check_contract_hash=contract.contract_hash,
            config_hash=config_hash,
            base_chain_budgets=budgets,
            effective_chain_budgets=budgets,
        )
        runs = self.project / ".forge" / "runs"
        child_dir = runs / self.child_id
        logs = child_dir / "logs"
        logs.mkdir(parents=True)
        integrity = {
            "config_integrity_version": forge.CONFIG_INTEGRITY_VERSION,
            "config_hash": config_hash,
            "config_snapshot_file": "config.snapshot.json",
            "base_chain_budgets": budgets.model_dump(mode="json"),
            "effective_chain_budgets": budgets.model_dump(mode="json"),
            "budget_extension_count": 0,
            "last_budget_extension_source_run_id": None,
        }
        forge.save_json(child_dir / "config.snapshot.json", config)
        forge.save_json(
            child_dir / "run.json",
            {
                "schema_version": forge.SCHEMA_VERSION,
                "run_id": self.child_id,
                "parent_run_id": self.failed_id,
                "continuation_chain_id": self.chain_id,
                "goal": self.goal,
                "config": config,
                "project_id": consumed.project_id,
                "plan_id": consumed.plan_id,
                "plan_hash": legacy_target_hash,
                "resume": {
                    "source_run_id": self.failed_id,
                    "source_config_hash": config_hash,
                    "post_worker_decision_recovery": {
                        "action": forge.POST_WORKER_DECISION_RECOVERY_ACTION,
                        "source_packet_id": legacy_journal[
                            "source_packet_id"
                        ],
                        "replacement_packet_id": replacement_id,
                        "raw_decision_sha256": self.expected_sha,
                    },
                },
                **integrity,
            },
        )
        adaptive.atomic_json(
            child_dir / "project-plan.initial.json",
            legacy_target.model_dump(mode="json"),
        )
        adaptive.atomic_json(
            child_dir / "project-plan.pre-worker-01.json",
            pre_worker_plan.model_dump(mode="json"),
        )
        adaptive.atomic_json(
            child_dir / "project-plan.result.json",
            consumed.model_dump(mode="json"),
        )
        adaptive.atomic_json(
            child_dir / "check-contract.snapshot.json",
            contract.model_dump(mode="json"),
        )
        recovery_record = dict(context["post_worker_decision_recovery"])
        recovery_record.update(
            {
                "journal_state": "target_applied",
                "journal_target_plan_hash": legacy_target_hash,
                "recovered_plan_hash": legacy_target_hash,
                "source_packet_attempts_preserved": True,
                "replacement_packet_attempts_at_replan": maximum,
                "replacement_recovery_authorized_at_replan": True,
                "replacement_recovery_used_at_replan": False,
            }
        )
        forge.save_json(
            child_dir / "decision-recovery.json", recovery_record
        )
        forge.save_json(
            logs / "01-decision.json",
            initial_decision.model_dump(mode="json"),
        )
        forge.save_json(
            logs / "01-worker.json",
            forge.WorkerResult(
                exit_code=0,
                summary="One valid worker transition completed.",
                raw_output="ok",
                duration_seconds=1.0,
                model="sonnet",
                effort="medium",
                valid_worker_outcome=True,
            ),
        )
        forge.save_json(logs / "01-checks.json", [check])
        forge.save_json(
            logs / "01-post-worker-evidence-index.json",
            {"repository_fingerprint": fingerprint},
        )
        forge.save_json(
            logs / "02-decision.json",
            final_decision.model_dump(mode="json"),
        )
        child_result = {
            "schema_version": forge.SCHEMA_VERSION,
            "run_id": self.child_id,
            "parent_run_id": self.failed_id,
            "continuation_chain_id": self.chain_id,
            "goal": self.goal,
            "final_status": "needs_continuation",
            "stop_reason_code": "packet_attempts_exhausted",
            "automatic_resume_allowed": False,
            "needs_human": True,
            "final_message": "The legacy replacement exhausted its one-shot slot.",
            "error": None,
            "final_decision": final_decision.model_dump(mode="json"),
            "checks": [check],
            "checks_passed": True,
            "continuation": continuation.model_dump(mode="json"),
            "repository_fingerprint": fingerprint,
            "project_id": consumed.project_id,
            "plan_id": consumed.plan_id,
            "plan_hash": consumed_hash,
            "active_packet_id": replacement_id,
            "check_contract_hash": contract.contract_hash,
            "last_check_tier": check["tier"],
            "chain_child_runs": 3,
            "chain_codex_calls": 6,
            "chain_worker_calls": 4,
            "chain_elapsed_seconds": 130.0,
            "chain_full_check_suites": 1,
            "chain_premium_escalations": 0,
            "chain_no_progress_events": 0,
            "chain_model_fallbacks": 0,
            "no_progress_count": 0,
            "failed_iterations": 0,
            "unavailable_models": {},
            **integrity,
        }
        forge.save_json(child_dir / "result.json", child_result)
        forge.save_json(
            child_dir / "telemetry.json",
            {
                "schema_version": forge.SCHEMA_VERSION,
                "run_id": self.child_id,
                "parent_run_id": self.failed_id,
                "continuation_chain_id": self.chain_id,
                "final_status": "needs_continuation",
                "child_run_index": 3,
                "chain_elapsed_seconds": 130.0,
                "budget_extension_count": 0,
                "chain_model_fallbacks": 0,
                "unavailable_models": {},
                "premium_escalations": 0,
            },
        )
        forge.save_json(
            self.project / ".forge" / "result.json", child_result
        )

    def load_context(self) -> dict:
        return forge.load_resume_context(
            self.project,
            self.child_id,
            resume_kind="explicit_human",
            authorize_packet_recovery=False,
        )

    def _write_normalization_journal(
        self, context: dict, target: adaptive.ProjectPlan
    ) -> dict:
        normalization = context[
            "recovery_attempt_budget_normalization"
        ]
        payload = {
            key: value
            for key, value in normalization.items()
            if key not in {"journal_state", "journal_target_plan_hash"}
        }
        payload.update(
            {
                "schema_version": forge.SCHEMA_VERSION,
                "prepared_by_run_id": "normalization-child",
                "created_at": "2026-07-25T02:00:00+00:00",
                "phase": "prepared",
                "child_run_id": None,
                "target_plan_hash": adaptive.plan_hash(target),
                "target_plan": target.model_dump(mode="json"),
            }
        )
        adaptive.atomic_json(
            forge._recovery_attempt_budget_normalization_journal_path(
                self.project, self.child_id
            ),
            payload,
        )
        return payload

    def test_read_only_eligibility_and_normal_attempt_transform(self) -> None:
        plan_path = self.project / ".forge" / "project-plan.json"
        before = plan_path.read_bytes()
        verdict = forge.resume_eligibility(
            self.project,
            self.child_id,
            supervisor_config=forge.load_config(
                Path(forge.__file__).with_name("forge.strict.config.json")
            ),
            in_wsl=False,
        )
        self.assertTrue(verdict["eligible"], verdict)
        self.assertEqual(
            verdict["action"],
            forge.RECOVERY_ATTEMPT_BUDGET_NORMALIZATION_ACTION,
        )
        self.assertTrue(
            verdict[
                "recovery_attempt_budget_normalization_eligible"
            ]
        )
        self.assertFalse(verdict["bounded_packet_recovery_eligible"])
        self.assertEqual(plan_path.read_bytes(), before)

        context = self.load_context()
        normalization = context[
            "recovery_attempt_budget_normalization"
        ]
        self.assertEqual(normalization["worker_call_delta"], 1)
        source_plan = adaptive.ProjectPlan.model_validate_json(
            plan_path.read_text(encoding="utf-8")
        )
        target = forge.apply_recovery_attempt_budget_normalization_plan(
            source_plan,
            normalization,
            context["config"],
        )
        source_packet = source_plan.work_packets[0]
        target_packet = forge.active_plan_packet(target)
        self.assertEqual(source_packet.status, "superseded")
        self.assertIsNotNone(target_packet)
        assert target_packet is not None
        self.assertEqual(target_packet.attempts, 1)
        self.assertFalse(
            target_packet.final_review_recovery_authorized
        )
        self.assertFalse(target_packet.final_review_recovery_used)
        reconstructed = target.model_copy(deep=True)
        reconstructed.updated_at = source_plan.updated_at
        reconstructed_packet = forge.active_plan_packet(reconstructed)
        assert reconstructed_packet is not None
        source_active = forge.active_plan_packet(source_plan)
        assert source_active is not None
        reconstructed_packet.attempts = source_active.attempts
        reconstructed_packet.final_review_recovery_authorized = (
            source_active.final_review_recovery_authorized
        )
        reconstructed_packet.final_review_recovery_used = (
            source_active.final_review_recovery_used
        )
        self.assertEqual(
            reconstructed.model_dump(mode="json"),
            source_plan.model_dump(mode="json"),
        )
        dispatched, was_recovery = adaptive.begin_packet_attempt(
            target,
            target_packet.packet_id,
            context["config"],
        )
        self.assertFalse(was_recovery)
        self.assertEqual(
            forge.active_plan_packet(dispatched).attempts, 2
        )

    def test_wal_accepts_only_exact_source_or_exact_target(self) -> None:
        context = self.load_context()
        plan_path = self.project / ".forge" / "project-plan.json"
        source = adaptive.ProjectPlan.model_validate_json(
            plan_path.read_text(encoding="utf-8")
        )
        target = forge._prepare_recovery_plan_for_persistence(
            forge.apply_recovery_attempt_budget_normalization_plan(
                source,
                context["recovery_attempt_budget_normalization"],
                context["config"],
            )
        )
        self._write_normalization_journal(context, target)
        intent = self.load_context()
        self.assertEqual(
            intent["recovery_attempt_budget_normalization"][
                "journal_state"
            ],
            "intent_only",
        )
        adaptive.atomic_json(plan_path, target.model_dump(mode="json"))
        applied = self.load_context()
        self.assertEqual(
            applied["recovery_attempt_budget_normalization"][
                "journal_state"
            ],
            "target_applied",
        )
        self.assertEqual(
            applied["continuation"]["plan_hash"],
            adaptive.plan_hash(target),
        )
        tampered = target.model_copy(deep=True)
        forge.active_plan_packet(tampered).objective += " tampered"
        adaptive.atomic_json(plan_path, tampered.model_dump(mode="json"))
        with self.assertRaisesRegex(RuntimeError, "differs from both"):
            self.load_context()
        adaptive.atomic_json(plan_path, target.model_dump(mode="json"))
        forge._mark_recovery_attempt_budget_normalization_child_started(
            self.project,
            self.child_id,
            "normalization-child",
        )
        with self.assertRaisesRegex(RuntimeError, "replay is forbidden"):
            self.load_context()

    def test_exact_human_green_lineage_and_maximum_are_required(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "exact source run ID"):
            forge.load_resume_context(
                self.project,
                "latest",
                resume_kind="explicit_human",
            )
        for resume_kind in ("direct_manual", "internal_automatic"):
            with self.subTest(resume_kind=resume_kind):
                with self.assertRaisesRegex(
                    RuntimeError, "explicit human supervised"
                ):
                    forge.load_resume_context(
                        self.project,
                        self.child_id,
                        resume_kind=resume_kind,
                    )

        result_path = (
            self.project
            / ".forge"
            / "runs"
            / self.child_id
            / "result.json"
        )
        original_result = result_path.read_bytes()
        result = json.loads(original_result)
        result["chain_worker_calls"] = 5
        result["continuation"]["chain_worker_calls"] = 5
        result_path.write_text(json.dumps(result), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "exactly one worker"):
            self.load_context()
        result_path.write_bytes(original_result)

        telemetry_path = (
            self.project
            / ".forge"
            / "runs"
            / self.child_id
            / "telemetry.json"
        )
        original_telemetry = telemetry_path.read_bytes()
        counter_tampers = (
            ("chain_child_runs", 4, "child_run_index"),
            ("chain_codex_calls", 7, None),
            ("chain_elapsed_seconds", 119.0, "chain_elapsed_seconds"),
            ("chain_full_check_suites", 2, None),
            ("chain_premium_escalations", 1, "premium_escalations"),
            ("chain_no_progress_events", 1, None),
            ("chain_model_fallbacks", 1, "chain_model_fallbacks"),
        )
        for field, value, telemetry_field in counter_tampers:
            with self.subTest(counter=field):
                result = json.loads(original_result)
                result[field] = value
                result["continuation"][field] = value
                result_path.write_text(
                    json.dumps(result), encoding="utf-8"
                )
                if telemetry_field is not None:
                    telemetry = json.loads(original_telemetry)
                    telemetry[telemetry_field] = value
                    telemetry_path.write_text(
                        json.dumps(telemetry), encoding="utf-8"
                    )
                with self.assertRaisesRegex(
                    RuntimeError, "counters do not represent"
                ):
                    self.load_context()
                result_path.write_bytes(original_result)
                telemetry_path.write_bytes(original_telemetry)

        checks_path = (
            self.project
            / ".forge"
            / "runs"
            / self.child_id
            / "logs"
            / "01-checks.json"
        )
        original_checks = checks_path.read_bytes()
        checks = json.loads(original_checks)
        checks[0]["exit_code"] = 1
        checks_path.write_text(json.dumps(checks), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "one valid green"):
            self.load_context()
        checks_path.write_bytes(original_checks)

        run_path = (
            self.project / ".forge" / "runs" / self.child_id / "run.json"
        )
        config_path = (
            self.project
            / ".forge"
            / "runs"
            / self.child_id
            / "config.snapshot.json"
        )
        original_run = run_path.read_bytes()
        original_config = config_path.read_bytes()
        run = json.loads(original_run)
        config = json.loads(original_config)
        config["max_packet_attempts"] = 1
        new_hash = adaptive.config_hash(config)
        run["config"] = config
        run["config_hash"] = new_hash
        run_path.write_text(json.dumps(run), encoding="utf-8")
        config_path.write_text(json.dumps(config), encoding="utf-8")
        result = json.loads(original_result)
        result["config_hash"] = new_hash
        result["continuation"]["config_hash"] = new_hash
        result_path.write_text(json.dumps(result), encoding="utf-8")
        with self.assertRaises(RuntimeError):
            self.load_context()
        run_path.write_bytes(original_run)
        config_path.write_bytes(original_config)
        result_path.write_bytes(original_result)

    def test_locked_wal_marks_child_before_worker_and_refunds_attempt(self) -> None:
        supervisor = forge.load_config(
            Path(forge.__file__).with_name("forge.strict.config.json")
        )
        source_directory = (
            self.project / ".forge" / "runs" / self.child_id
        )
        source_hashes = {
            path.relative_to(source_directory).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in source_directory.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        legacy_journal_path = forge._decision_recovery_journal_path(
            self.project, self.failed_id
        )
        legacy_journal_hash = hashlib.sha256(
            legacy_journal_path.read_bytes()
        ).hexdigest()
        with (
            mock.patch.object(
                forge, "codex_auth_status", return_value=(True, "ok")
            ),
            mock.patch.object(
                forge,
                "claude_auth_status",
                return_value=(True, "ok"),
            ),
            mock.patch.object(
                forge,
                "runtime_cli_preflight",
                return_value={
                    "tools": {
                        "claude": {
                            "capabilities": {
                                "model": True,
                                "effort": True,
                                "max_turns": False,
                            }
                        }
                    }
                },
            ),
            mock.patch.object(
                forge,
                "run_claude_routed",
                side_effect=RuntimeError("simulated transport crash"),
            ),
        ):
            code = forge.resume_forge(
                self.project,
                self.child_id,
                resume_kind="explicit_human",
                supervisor_config=supervisor,
            )
        self.assertEqual(code, forge.EXIT_FAILED)
        self.assertEqual(
            source_hashes,
            {
                path.relative_to(source_directory).as_posix(): (
                    hashlib.sha256(path.read_bytes()).hexdigest()
                )
                for path in source_directory.rglob("*")
                if path.is_file() and not path.is_symlink()
            },
        )
        self.assertEqual(
            hashlib.sha256(legacy_journal_path.read_bytes()).hexdigest(),
            legacy_journal_hash,
        )
        journal = (
            forge._load_recovery_attempt_budget_normalization_journal(
                self.project, self.child_id
            )
        )
        self.assertIsNotNone(journal)
        assert journal is not None
        self.assertEqual(journal["phase"], "child_started")
        self.assertRegex(journal["child_run_id"], r"^[0-9-]+$")
        current = adaptive.ProjectPlan.model_validate_json(
            (
                self.project / ".forge" / "project-plan.json"
            ).read_text(encoding="utf-8")
        )
        active = forge.active_plan_packet(current)
        self.assertIsNotNone(active)
        assert active is not None
        self.assertEqual(active.attempts, 1)
        self.assertFalse(active.final_review_recovery_authorized)
        self.assertFalse(active.final_review_recovery_used)
        with self.assertRaisesRegex(RuntimeError, "replay is forbidden"):
            self.load_context()


@unittest.skipUnless(
    os.environ.get("FORGE_TEST_REAL_DECISION_RECOVERY") == "1"
    and forge.running_in_wsl()
    and bool(REAL_RECOVERY_PROJECT)
    and Path(REAL_RECOVERY_PROJECT).is_dir()
    and bool(REAL_RECOVERY_RUN_ID)
    and len(REAL_RECOVERY_SHA) == 64
    and set(REAL_RECOVERY_SHA) <= set("0123456789abcdef"),
    "Opt-in read-only test for the authorized WSL project fixture.",
)
class RealDecisionRecoveryFixtureTests(unittest.TestCase):
    def test_actual_failed_run_is_read_only_eligible(self) -> None:
        project = Path(REAL_RECOVERY_PROJECT)
        plan_path = project / ".forge" / "project-plan.json"
        before = plan_path.read_bytes()
        verdict = forge.resume_eligibility(
            project,
            REAL_RECOVERY_RUN_ID,
            supervisor_config=forge.load_config(
                Path(forge.__file__).with_name("forge.strict.config.json")
            ),
            in_wsl=True,
            expected_decision_recovery_sha256=REAL_RECOVERY_SHA,
        )
        self.assertTrue(verdict["eligible"], verdict)
        self.assertEqual(
            verdict["action"],
            forge.POST_WORKER_DECISION_RECOVERY_ACTION,
        )
        self.assertEqual(plan_path.read_bytes(), before)


@unittest.skipUnless(
    os.environ.get("FORGE_TEST_REAL_BUDGET_NORMALIZATION") == "1"
    and forge.running_in_wsl()
    and bool(REAL_BUDGET_NORMALIZATION_PROJECT)
    and Path(REAL_BUDGET_NORMALIZATION_PROJECT).is_dir()
    and bool(REAL_BUDGET_NORMALIZATION_RUN_ID),
    "Opt-in read-only test for an authorized legacy recovery child.",
)
class RealRecoveryAttemptBudgetNormalizationFixtureTests(
    unittest.TestCase
):
    def test_actual_legacy_child_is_read_only_eligible(self) -> None:
        project = Path(REAL_BUDGET_NORMALIZATION_PROJECT)
        plan_path = project / ".forge" / "project-plan.json"
        before = plan_path.read_bytes()
        verdict = forge.resume_eligibility(
            project,
            REAL_BUDGET_NORMALIZATION_RUN_ID,
            supervisor_config=forge.load_config(
                Path(forge.__file__).with_name("forge.strict.config.json")
            ),
            in_wsl=True,
        )
        self.assertTrue(verdict["eligible"], verdict)
        self.assertEqual(
            verdict["action"],
            forge.RECOVERY_ATTEMPT_BUDGET_NORMALIZATION_ACTION,
        )
        self.assertEqual(plan_path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
