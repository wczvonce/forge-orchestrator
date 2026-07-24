from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import forge
import forge_adaptive as adaptive


class PacketAttemptRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def plan(*, attempts: int = 0) -> adaptive.ProjectPlan:
        packet = adaptive.WorkPacket(
            packet_id="packet-001",
            title="Repair packet",
            objective="Repair the exact issue.",
            acceptance_criteria=["The exact issue is repaired."],
            status="in_progress",
            check_tier="targeted",
            attempts=attempts,
        )
        return adaptive.ProjectPlan(
            plan_id="plan-1",
            project_id="project-1",
            goal_hash="goal-hash",
            spec_hash="spec-hash",
            created_at="2026-07-24T00:00:00+00:00",
            updated_at="2026-07-24T00:00:00+00:00",
            status="active",
            active_packet_id=packet.packet_id,
            work_packets=[packet],
        )

    @staticmethod
    def config() -> dict:
        config = forge.DEFAULT_CONFIG.copy()
        config["max_packet_attempts"] = 3
        config["adaptive_profiles"] = json.loads(
            json.dumps(forge.DEFAULT_CONFIG["adaptive_profiles"])
        )
        return config

    def write_adaptive_resume_source(
        self,
        *,
        goal: str = "Continue the exact adaptive packet.",
        run_id: str = "adaptive-source",
    ) -> tuple[str, forge.ContinuationPayload]:
        forge.ensure_git_repo(self.project)
        identity = adaptive.stable_project_identity(self.project)
        config = self.config()
        config.update(
            {
                "adaptive_orchestration": True,
                "runtime_preflight": False,
                "auto_detect_checks": False,
                "check_definitions": [],
                "checks": [],
            }
        )
        contract = forge.ensure_check_contract(self.project, config)
        plan = adaptive.ProjectPlan(
            plan_id="adaptive-plan",
            project_id=identity["project_id"],
            goal_hash=adaptive.sha256_text(goal),
            spec_hash=adaptive.sha256_text(""),
            created_at="2026-07-24T00:00:00+00:00",
            updated_at="2026-07-24T00:00:00+00:00",
            status="active",
            active_packet_id="packet-001",
            work_packets=[
                adaptive.WorkPacket(
                    packet_id="packet-001",
                    title="Adaptive packet",
                    objective="Continue safely.",
                    acceptance_criteria=["The exact packet is complete."],
                    status="in_progress",
                )
            ],
            check_contract_hash=contract.contract_hash,
        )
        adaptive.save_plan(self.project, plan)
        persisted_plan = adaptive.ProjectPlan.model_validate_json(
            (self.project / ".forge" / "project-plan.json").read_text(
                encoding="utf-8"
            )
        )
        snapshot = forge._canonical_config_snapshot(config)
        snapshot_hash = adaptive.config_hash(snapshot)
        budgets = adaptive.ChainBudgets.model_validate(config["chain_budgets"])
        continuation = forge.ContinuationPayload(
            source_run_id=run_id,
            continuation_chain_id=run_id,
            next_prompt="Continue safely.",
            acceptance_criteria=["The exact packet is complete."],
            repository_fingerprint=forge.repo_fingerprint(self.project),
            repository_manifest=forge.repo_manifest(self.project),
            project_id=identity["project_id"],
            plan_id=persisted_plan.plan_id,
            plan_hash=adaptive.plan_hash(persisted_plan),
            active_packet_id="packet-001",
            check_contract_hash=contract.contract_hash,
            config_hash=snapshot_hash,
            base_chain_budgets=budgets,
            effective_chain_budgets=budgets,
        )
        run_directory = self.project / ".forge" / "runs" / run_id
        run_directory.mkdir(parents=True)
        integrity = {
            "config_integrity_version": forge.CONFIG_INTEGRITY_VERSION,
            "config_hash": snapshot_hash,
            "config_snapshot_file": "config.snapshot.json",
            "base_chain_budgets": budgets.model_dump(mode="json"),
            "effective_chain_budgets": budgets.model_dump(mode="json"),
            "budget_extension_count": 0,
            "last_budget_extension_source_run_id": None,
        }
        forge.save_json(run_directory / "config.snapshot.json", snapshot)
        forge.save_json(
            run_directory / "run.json",
            {
                "schema_version": forge.SCHEMA_VERSION,
                "run_id": run_id,
                "goal": goal,
                "config": config,
                **integrity,
            },
        )
        forge.save_json(
            run_directory / "result.json",
            {
                "schema_version": forge.SCHEMA_VERSION,
                "run_id": run_id,
                "parent_run_id": None,
                "continuation_chain_id": run_id,
                "goal": goal,
                "final_status": "needs_continuation",
                "stop_reason_code": "reviewer_continue",
                "automatic_resume_allowed": True,
                "continuation": continuation.model_dump(mode="json"),
                **integrity,
            },
        )
        return goal, continuation

    def test_transport_dispatch_consumes_chain_call_but_not_logical_attempt(self):
        plan, recovery = adaptive.begin_packet_attempt(
            self.plan(),
            "packet-001",
            self.config(),
        )
        decision = forge.Decision(
            status="continue",
            assessment="Repair.",
            active_packet_id="packet-001",
            next_prompt="Repair the exact issue.",
            acceptance_criteria=["The exact issue is repaired."],
        )
        logs = self.project / "logs"
        logs.mkdir()
        with mock.patch.object(
            forge,
            "run_claude",
            side_effect=BrokenPipeError("simulated transport break"),
        ):
            outcome = forge.run_claude_routed(
                self.project,
                "Goal",
                decision,
                self.config(),
                profile="standard",
                routing_reason="test",
                iteration=1,
                logs=logs,
                max_worker_calls_remaining=3,
                max_premium_calls_remaining=0,
            )
        self.assertEqual(outcome.worker_calls, 1)
        self.assertFalse(outcome.worker.valid_worker_outcome)
        self.assertEqual(outcome.worker.termination_reason, "transport_failure")
        self.assertEqual(
            forge.claude_escalation_reasons(
                worker=outcome.worker,
                checks=[],
                failed_iterations=2,
                no_progress_count=2,
                progress_made=False,
                repeated_failure_count=2,
                escalations_used=0,
                config=self.config(),
            ),
            [],
        )

        refunded = adaptive.refund_packet_attempt(
            plan,
            "packet-001",
            recovery_attempt=recovery,
        )
        self.assertEqual(refunded.work_packets[0].attempts, 0)
        self.assertEqual(outcome.worker_calls, 1)

    def test_exactly_one_recovery_and_transport_refund(self):
        plan, authorized = adaptive.authorize_final_review_recovery(
            self.plan(attempts=3),
            "packet-001",
            self.config(),
        )
        self.assertTrue(authorized)
        self.assertFalse(
            adaptive.packet_attempt_budget_exhausted(plan.work_packets[0], self.config())
        )

        plan, recovery = adaptive.begin_packet_attempt(
            plan,
            "packet-001",
            self.config(),
        )
        self.assertTrue(recovery)
        self.assertEqual(plan.work_packets[0].attempts, 4)
        self.assertTrue(plan.work_packets[0].final_review_recovery_used)
        self.assertTrue(
            adaptive.packet_attempt_budget_exhausted(plan.work_packets[0], self.config())
        )

        plan = adaptive.refund_packet_attempt(
            plan,
            "packet-001",
            recovery_attempt=True,
        )
        self.assertEqual(plan.work_packets[0].attempts, 3)
        self.assertTrue(plan.work_packets[0].final_review_recovery_authorized)
        self.assertFalse(plan.work_packets[0].final_review_recovery_used)

        plan, recovery = adaptive.begin_packet_attempt(
            plan,
            "packet-001",
            self.config(),
        )
        self.assertTrue(recovery)
        plan_again, authorized_again = adaptive.authorize_final_review_recovery(
            plan,
            "packet-001",
            self.config(),
        )
        self.assertFalse(authorized_again)
        self.assertIs(plan_again, plan)

    def test_final_review_recovery_accepts_green_required_tier_only(self):
        decision = forge.Decision(
            status="continue",
            decision_kind="repair_packet",
            assessment="One bounded repair remains.",
            active_packet_id="packet-001",
            next_prompt="Change only the incorrect sentence.",
            acceptance_criteria=["The sentence is correct."],
        )
        checks = [
            forge.CheckResult(
                command="targeted check",
                exit_code=0,
                output="ok",
                check_id="targeted",
                tier="targeted",
            )
        ]
        updated, authorized = forge.maybe_authorize_final_review_recovery(
            self.plan(attempts=3),
            decision,
            checks,
            config=self.config(),
            last_check_tier="targeted",
            no_progress_count=0,
            failed_iterations=0,
            budget_reason=None,
        )
        self.assertTrue(authorized)
        self.assertTrue(
            updated.work_packets[0].final_review_recovery_authorized
        )

        _, authorized_with_no_progress = (
            forge.maybe_authorize_final_review_recovery(
                self.plan(attempts=3),
                decision,
                checks,
                config=self.config(),
                last_check_tier="targeted",
                no_progress_count=1,
                failed_iterations=0,
                budget_reason=None,
            )
        )
        self.assertFalse(authorized_with_no_progress)

    def test_old_plan_hash_and_resume_remain_compatible(self):
        goal = "Continue the exact packet."
        forge.ensure_git_repo(self.project)
        identity = adaptive.stable_project_identity(self.project)
        config = self.config()
        config.update(
            {
                "adaptive_orchestration": True,
                "auto_detect_checks": False,
                "check_definitions": [],
                "checks": [],
            }
        )
        contract = forge.ensure_check_contract(self.project, config)
        plan = adaptive.ProjectPlan(
            plan_id="legacy-plan",
            project_id=identity["project_id"],
            goal_hash=adaptive.sha256_text(goal),
            spec_hash=adaptive.sha256_text(""),
            created_at="2026-07-24T00:00:00+00:00",
            updated_at="2026-07-24T00:00:00+00:00",
            status="active",
            active_packet_id="packet-001",
            work_packets=[
                adaptive.WorkPacket(
                    packet_id="packet-001",
                    title="Legacy packet",
                    objective="Continue.",
                    acceptance_criteria=["Done."],
                    status="in_progress",
                )
            ],
            check_contract_hash=contract.contract_hash,
        )
        legacy_payload = plan.model_dump(mode="json")
        for packet in legacy_payload["work_packets"]:
            packet.pop("final_review_recovery_authorized")
            packet.pop("final_review_recovery_used")
        canonical = json.loads(json.dumps(legacy_payload))
        for key in ("updated_at", "last_validated_at", "last_validation_summary"):
            canonical.pop(key, None)
        legacy_hash = hashlib.sha256(
            json.dumps(
                canonical,
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        plan_path = self.project / ".forge" / "project-plan.json"
        plan_path.write_text(
            json.dumps(legacy_payload),
            encoding="utf-8",
        )
        loaded = adaptive.ProjectPlan.model_validate(legacy_payload)
        self.assertEqual(adaptive.plan_hash(loaded), legacy_hash)

        run_id = "legacy-source"
        run_directory = self.project / ".forge" / "runs" / run_id
        run_directory.mkdir(parents=True)
        (run_directory / "run.json").write_text(
            json.dumps({"goal": goal, "config": config}),
            encoding="utf-8",
        )
        continuation = forge.ContinuationPayload(
            source_run_id=run_id,
            continuation_chain_id=run_id,
            next_prompt="Continue.",
            acceptance_criteria=["Done."],
            repository_fingerprint=forge.repo_fingerprint(self.project),
            repository_manifest=forge.repo_manifest(self.project),
            project_id=identity["project_id"],
            plan_id=plan.plan_id,
            plan_hash=legacy_hash,
            active_packet_id="packet-001",
            chain_child_runs=0,
            chain_codex_calls=1,
            chain_no_progress_events=0,
            check_contract_hash=contract.contract_hash,
        )
        (run_directory / "result.json").write_text(
            json.dumps(
                {
                    "schema_version": forge.SCHEMA_VERSION,
                    "run_id": run_id,
                    "parent_run_id": None,
                    "continuation_chain_id": run_id,
                    "goal": goal,
                    "final_status": "needs_continuation",
                    "stop_reason_code": "reviewer_continue",
                    "automatic_resume_allowed": True,
                    "continuation": continuation.model_dump(mode="json"),
                }
            ),
            encoding="utf-8",
        )
        context = forge.load_resume_context(self.project, run_id)
        self.assertEqual(context["continuation"]["plan_hash"], legacy_hash)

    def test_resume_eligibility_does_not_recreate_missing_project_identity(self):
        _, _ = self.write_adaptive_resume_source()
        identity_path = self.project / ".forge" / "project.json"
        identity_path.unlink()
        plan_path = self.project / ".forge" / "project-plan.json"
        contract_path = self.project / ".forge" / "check-contract.json"
        plan_before = plan_path.read_bytes()
        contract_before = contract_path.read_bytes()

        eligibility = forge.resume_eligibility(self.project, "adaptive-source")

        self.assertFalse(eligibility["eligible"])
        self.assertFalse(eligibility["state_mutated"])
        self.assertFalse(identity_path.exists())
        self.assertEqual(plan_path.read_bytes(), plan_before)
        self.assertEqual(contract_path.read_bytes(), contract_before)
        self.assertIn("identity is missing", eligibility["message"])

    def test_child_run_revalidates_plan_hash_before_persistent_plan_write(self):
        goal, continuation = self.write_adaptive_resume_source()
        context = forge.load_resume_context(self.project, "adaptive-source")
        plan_path = self.project / ".forge" / "project-plan.json"
        changed_plan = adaptive.ProjectPlan.model_validate_json(
            plan_path.read_text(encoding="utf-8")
        )
        changed_plan.work_packets[0].objective = "Externally changed objective."
        changed_bytes = (
            json.dumps(
                changed_plan.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        ).encode("utf-8")
        plan_path.write_bytes(changed_bytes)

        with self.assertRaisesRegex(
            RuntimeError,
            "project plan changed outside the source run",
        ):
            forge.run_forge(
                self.project,
                goal,
                Path(forge.__file__).with_name("forge.config.json"),
                resume_context=context,
            )

        self.assertEqual(plan_path.read_bytes(), changed_bytes)
        with self.assertRaisesRegex(
            RuntimeError,
            "project plan changed outside the source run",
        ):
            forge.load_verified_adaptive_resume_state(
                self.project,
                continuation,
                goal=goal,
            )

    def test_child_run_revalidates_plan_after_baseline_before_initial_save(self):
        goal, _ = self.write_adaptive_resume_source()
        context = forge.load_resume_context(self.project, "adaptive-source")
        plan_path = self.project / ".forge" / "project-plan.json"
        changed_plan = adaptive.ProjectPlan.model_validate_json(
            plan_path.read_text(encoding="utf-8")
        )
        changed_plan.work_packets[0].objective = (
            "Concurrent change during the baseline scan."
        )
        changed_bytes = (
            json.dumps(
                changed_plan.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        ).encode("utf-8")

        def mutate_plan_during_baseline(_project: Path) -> dict:
            plan_path.write_bytes(changed_bytes)
            return {
                "head": None,
                "git_status_exit_code": 0,
                "git_status": "",
                "content_manifest": {},
                "content_fingerprint": "concurrent-change",
            }

        with mock.patch.object(
            forge,
            "git_baseline",
            side_effect=mutate_plan_during_baseline,
        ), self.assertRaisesRegex(
            RuntimeError,
            "project plan changed outside the source run",
        ):
            forge.run_forge(
                self.project,
                goal,
                Path(forge.__file__).with_name("forge.config.json"),
                resume_context=context,
            )

        self.assertEqual(plan_path.read_bytes(), changed_bytes)

    def test_project_run_lock_rejects_a_competing_writer(self):
        with forge.project_run_lock(
            self.project,
            create_forge_directory=True,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "already active",
            ):
                with forge.project_run_lock(
                    self.project,
                    create_forge_directory=True,
                ):
                    self.fail("A competing project writer acquired the lock.")

    def test_child_run_revalidates_contract_hash_before_persistent_plan_write(self):
        goal, _ = self.write_adaptive_resume_source()
        context = forge.load_resume_context(self.project, "adaptive-source")
        plan_path = self.project / ".forge" / "project-plan.json"
        plan_before = plan_path.read_bytes()
        contract_path = self.project / ".forge" / "check-contract.json"
        contract = adaptive.CheckContract.model_validate_json(
            contract_path.read_text(encoding="utf-8")
        )
        changed_contract = contract.model_dump(mode="json")
        changed_contract["change_reason"] = "Concurrent external contract rewrite."
        changed_contract["contract_hash"] = adaptive.check_contract_hash(
            changed_contract
        )
        contract_path.write_text(
            json.dumps(changed_contract, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "Check contract hash changed since the source run",
        ):
            forge.run_forge(
                self.project,
                goal,
                Path(forge.__file__).with_name("forge.config.json"),
                resume_context=context,
            )

        self.assertEqual(plan_path.read_bytes(), plan_before)

    def test_non_resumable_continuation_sets_supervisor_needs_human(self):
        forge_dir = self.project / ".forge"
        forge_dir.mkdir()
        (forge_dir / "result.json").write_text(
            json.dumps(
                {
                    "schema_version": forge.SCHEMA_VERSION,
                    "run_id": "source-run",
                    "final_status": "needs_continuation",
                    "stop_reason_code": "packet_attempts_exhausted",
                    "automatic_resume_allowed": False,
                    "final_message": "Packet attempts exhausted.",
                    "continuation": {"next_prompt": "Exact packet."},
                }
            ),
            encoding="utf-8",
        )
        config_path = Path(forge.__file__).with_name("forge.strict.config.json")
        with mock.patch.object(
            forge,
            "sandbox_runtime_available",
            return_value=True,
        ), mock.patch.object(
            forge,
            "run_forge",
            return_value=forge.EXIT_NEEDS_CONTINUATION,
        ):
            exit_code = forge.run_chain(
                self.project,
                "Goal",
                config_path,
            )
        self.assertEqual(exit_code, forge.EXIT_NEEDS_CONTINUATION)
        supervisor = json.loads(
            (forge_dir / "chain-supervisor.json").read_text(encoding="utf-8")
        )
        self.assertTrue(supervisor["needs_human"])

    def test_exhausted_child_migrates_exact_parent_final_repair_once(self):
        goal = "Finish the active packet."
        prompt = "Change only the incorrect security-boundary sentence."
        forge.ensure_git_repo(self.project)
        identity = adaptive.stable_project_identity(self.project)
        config = self.config()
        config.update(
            {
                "adaptive_orchestration": True,
                "auto_detect_checks": False,
                "check_definitions": [],
                "checks": [],
            }
        )
        contract = forge.ensure_check_contract(self.project, config)
        plan = adaptive.ProjectPlan(
            plan_id="plan-recovery",
            project_id=identity["project_id"],
            goal_hash=adaptive.sha256_text(goal),
            spec_hash=adaptive.sha256_text(""),
            created_at="2026-07-24T00:00:00+00:00",
            updated_at="2026-07-24T00:00:00+00:00",
            status="active",
            active_packet_id="packet-001",
            work_packets=[
                adaptive.WorkPacket(
                    packet_id="packet-001",
                    title="Documentation repair",
                    objective=prompt,
                    acceptance_criteria=["The sentence is evidence-accurate."],
                    status="in_progress",
                    check_tier="targeted",
                    attempts=3,
                )
            ],
            check_contract_hash=contract.contract_hash,
        )
        adaptive.save_plan(self.project, plan)
        original_hash = adaptive.plan_hash(plan)
        check = forge.CheckResult(
            command="targeted check",
            exit_code=0,
            output="ok",
            check_id="targeted",
            tier="targeted",
        )

        def continuation(run_id: str, child_runs: int) -> forge.ContinuationPayload:
            return forge.ContinuationPayload(
                source_run_id=run_id,
                continuation_chain_id="chain-1",
                next_prompt=prompt,
                acceptance_criteria=["The sentence is evidence-accurate."],
                last_check_results=[check],
                repository_fingerprint=forge.repo_fingerprint(self.project),
                repository_manifest=forge.repo_manifest(self.project),
                no_progress_count=0,
                failed_iterations=0,
                chain_worker_calls=2,
                chain_elapsed_seconds=30,
                chain_full_check_suites=1,
                project_id=identity["project_id"],
                plan_id=plan.plan_id,
                plan_hash=original_hash,
                active_packet_id="packet-001",
                chain_child_runs=child_runs,
                chain_codex_calls=3,
                chain_no_progress_events=0,
                check_contract_hash=contract.contract_hash,
            )

        runs = self.project / ".forge" / "runs"
        parent_id = "parent-review"
        parent = runs / parent_id
        parent.mkdir(parents=True)
        (parent / "run.json").write_text(
            json.dumps({"goal": goal, "config": config}),
            encoding="utf-8",
        )
        parent_decision = forge.Decision(
            status="continue",
            decision_kind="repair_packet",
            assessment="One small repair remains.",
            active_packet_id="packet-001",
            next_prompt=prompt,
            acceptance_criteria=["The sentence is evidence-accurate."],
            check_tier="targeted",
        )
        (parent / "result.json").write_text(
            json.dumps(
                {
                    "schema_version": forge.SCHEMA_VERSION,
                    "run_id": parent_id,
                    "parent_run_id": None,
                    "continuation_chain_id": "chain-1",
                    "goal": goal,
                    "final_status": "needs_continuation",
                    "stop_reason_code": "reviewer_continue",
                    "automatic_resume_allowed": True,
                    "final_decision": parent_decision.model_dump(mode="json"),
                    "checks": [check.model_dump(mode="json")],
                    "checks_passed": True,
                    "last_check_tier": "targeted",
                    "continuation": continuation(
                        parent_id,
                        0,
                    ).model_dump(mode="json"),
                }
            ),
            encoding="utf-8",
        )

        child_id = "attempt-stop"
        child = runs / child_id
        child.mkdir()
        (child / "run.json").write_text(
            json.dumps({"goal": goal, "config": config}),
            encoding="utf-8",
        )
        child_decision = forge.Decision(
            status="continue",
            decision_kind="implement_packet",
            assessment="Exact inherited continuation.",
            active_packet_id="packet-001",
            next_prompt=prompt,
            acceptance_criteria=["The sentence is evidence-accurate."],
            check_tier="targeted",
        )
        (child / "result.json").write_text(
            json.dumps(
                {
                    "schema_version": forge.SCHEMA_VERSION,
                    "run_id": child_id,
                    "parent_run_id": parent_id,
                    "continuation_chain_id": "chain-1",
                    "goal": goal,
                    "final_status": "needs_continuation",
                    "stop_reason_code": "packet_attempts_exhausted",
                    "automatic_resume_allowed": False,
                    "final_decision": child_decision.model_dump(mode="json"),
                    "checks": [check.model_dump(mode="json")],
                    "checks_passed": True,
                    "last_check_tier": "targeted",
                    "continuation": continuation(
                        child_id,
                        1,
                    ).model_dump(mode="json"),
                }
            ),
            encoding="utf-8",
        )

        plan_before_eligibility = (
            self.project / ".forge" / "project-plan.json"
        ).read_bytes()
        eligibility = forge.resume_eligibility(self.project, child_id)
        self.assertTrue(eligibility["eligible"])
        self.assertEqual(
            eligibility["action"],
            "bounded_final_review_recovery",
        )
        self.assertTrue(eligibility["bounded_packet_recovery_eligible"])
        self.assertEqual(eligibility["model_calls_made"], 0)
        self.assertFalse(eligibility["state_mutated"])
        self.assertEqual(
            (
                self.project / ".forge" / "project-plan.json"
            ).read_bytes(),
            plan_before_eligibility,
        )

        context = forge.load_resume_context(self.project, child_id)
        self.assertEqual(
            context["recovery_authorized_from_run_id"],
            parent_id,
        )
        self.assertEqual(context["continuation"]["next_prompt"], prompt)
        migrated = adaptive.ProjectPlan.model_validate_json(
            (self.project / ".forge" / "project-plan.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertTrue(
            migrated.work_packets[0].final_review_recovery_authorized
        )
        self.assertNotEqual(context["continuation"]["plan_hash"], original_hash)


if __name__ == "__main__":
    unittest.main()
