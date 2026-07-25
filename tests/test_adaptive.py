from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import forge_adaptive as adaptive
import forge
from pydantic import ValidationError


class AdaptiveSchemaTests(unittest.TestCase):
    def packet(self, **overrides):
        payload = {
            "packet_id": "packet-001",
            "title": "Create foundation",
            "objective": "Create a safe project foundation.",
            "acceptance_criteria": ["Foundation works", "Targeted checks pass"],
        }
        payload.update(overrides)
        return adaptive.WorkPacket(**payload)

    def test_work_packet_rejects_unknown_fields(self):
        with self.assertRaises(ValidationError):
            adaptive.WorkPacket(
                packet_id="packet-001",
                title="Test",
                objective="Test",
                acceptance_criteria=["Pass"],
                invented_model="expensive",
            )

    def test_work_packet_has_one_to_four_acceptance_criteria(self):
        with self.assertRaises(ValidationError):
            self.packet(acceptance_criteria=[])
        with self.assertRaises(ValidationError):
            self.packet(acceptance_criteria=["1", "2", "3", "4", "5"])

    def test_economy_is_rejected_for_high_risk_packet(self):
        with self.assertRaises(ValidationError):
            self.packet(risk="high", recommended_worker_profile="economy")

    def test_decision_schema_is_strict_and_versioned(self):
        schema = adaptive.AdaptiveDecision.model_json_schema()
        self.assertEqual(schema["additionalProperties"], False)
        decision = adaptive.AdaptiveDecision(
            status="continue",
            assessment="Implement",
            next_prompt="Implement packet.",
        )
        self.assertEqual(decision.schema_version, adaptive.ADAPTIVE_SCHEMA_VERSION)

    def test_continue_requires_prompt(self):
        with self.assertRaises(ValidationError):
            adaptive.AdaptiveDecision(status="continue", assessment="Missing prompt")

    def test_contract_drift_approval_is_explicit_and_reasoned(self):
        ordinary = adaptive.AdaptiveDecision(
            status="continue",
            assessment="Continue normally",
            next_prompt="Implement packet.",
        )
        self.assertFalse(ordinary.approve_check_contract_drift)
        self.assertEqual(ordinary.check_contract_approval_reason, "")
        with self.assertRaises(ValidationError):
            adaptive.AdaptiveDecision(
                status="continue",
                assessment="Approve without evidence reason",
                next_prompt="Implement packet.",
                approve_check_contract_drift=True,
            )
        normalized = adaptive.AdaptiveDecision(
            status="continue",
            assessment="Ambiguous reason",
            next_prompt="Implement packet.",
            check_contract_approval_reason="Looks fine.",
        )
        self.assertEqual(normalized.check_contract_approval_reason, "")
        self.assertTrue(normalized.normalization_warnings)

    def test_lean_architecture_requires_every_worker_prompt(self):
        packets = [
            self.packet(
                packet_id=f"packet-{index:03d}",
                expected_paths=(
                    ["src/app.py"] if index == 2 else ["docs/packet.md"]
                ),
                worker_prompt=(
                    "Implement the bounded packet and run targeted checks."
                    if index != 3
                    else None
                ),
            )
            for index in range(1, 5)
        ]
        with self.assertRaisesRegex(ValueError, "packet-003"):
            adaptive.validate_lean_initial_plan(packets)
        packets[2].worker_prompt = "Implement packet 3 and run its checks."
        adaptive.validate_lean_initial_plan(packets)

    def test_lean_plan_rejects_document_heavy_start(self):
        packets = [
            self.packet(
                packet_id=f"packet-{index:03d}",
                packet_type=("code" if index == 3 else "docs"),
                worker_prompt=f"Complete packet {index}.",
                expected_paths=(
                    ["src/app.py"] if index == 3 else [f"docs/{index}.md"]
                ),
            )
            for index in range(1, 6)
        ]
        with self.assertRaisesRegex(ValueError, "at most two"):
            adaptive.validate_lean_initial_plan(packets)

    def test_lean_plan_accepts_walking_skeleton_in_packet_two(self):
        packets = [
            self.packet(
                packet_id=f"packet-{index:03d}",
                packet_type=("docs" if index == 1 else "code"),
                worker_prompt=f"Complete packet {index}.",
                expected_paths=(
                    ["docs/plan.md"]
                    if index == 1
                    else ["src/main.py"]
                    if index == 2
                    else [f"src/feature_{index}.py"]
                ),
            )
            for index in range(1, 5)
        ]
        adaptive.validate_lean_initial_plan(packets)

    def test_worker_prompt_and_packet_type_are_backward_compatible(self):
        legacy = self.packet()
        self.assertEqual(legacy.packet_type, "code")
        self.assertIsNone(legacy.worker_prompt)
        docs = self.packet(
            packet_type="docs",
            worker_prompt="Update README.md only and run git diff --check.",
        )
        self.assertEqual(docs.packet_type, "docs")
        self.assertIn("README.md", docs.worker_prompt or "")

    def test_read_only_claude_reviewer_uses_shared_router_without_write_tools(self):
        packet = self.packet(
            worker_prompt="Implement packet.",
            check_tier="milestone",
        )
        worker = forge.WorkerResult(
            exit_code=0,
            summary=json.dumps(
                {
                    "approve": False,
                    "issues": [
                        {
                            "file_path": "src/app.py",
                            "description": "Handle the empty state.",
                        }
                    ],
                }
            ),
            raw_output="",
            duration_seconds=0.1,
            termination_reason="success",
            valid_worker_outcome=True,
        )
        routed = forge.RoutedWorkerOutcome(worker=worker, worker_calls=1)
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(
            forge,
            "run_claude_routed",
            return_value=routed,
        ) as mocked:
            verdict, outcome = forge.run_read_only_claude_review(
                Path(temp),
                "Build app",
                packet,
                [
                    forge.CheckResult(
                        command="test",
                        exit_code=0,
                        output="Ran 1 tests",
                    )
                ],
                forge.DEFAULT_CONFIG,
                iteration=1,
                logs=Path(temp) / "logs",
                status=None,
                unavailable_models={},
                max_worker_calls_remaining=2,
                max_premium_calls_remaining=1,
            )
        self.assertFalse(verdict.approve)
        self.assertEqual(outcome.worker_calls, 1)
        kwargs = mocked.call_args.kwargs
        self.assertEqual(kwargs["profile"], "claude_reviewer")
        self.assertEqual(kwargs["tools_override"], "Read,Glob,Grep")
        self.assertTrue(kwargs["read_only"])
        self.assertNotIn("Write", kwargs["tools_override"])
        self.assertNotIn("Edit", kwargs["tools_override"])
        self.assertNotIn("Bash", kwargs["tools_override"])


class ProjectPlanTests(unittest.TestCase):
    def packet(self, packet_id="packet-001", **overrides):
        payload = {
            "packet_id": packet_id,
            "title": packet_id,
            "objective": f"Implement {packet_id}.",
            "acceptance_criteria": [f"{packet_id} works"],
        }
        payload.update(overrides)
        return adaptive.WorkPacket(**payload)

    def test_stable_project_identity_and_plan_persist(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            first = adaptive.stable_project_identity(project)
            second = adaptive.stable_project_identity(project)
            self.assertEqual(first["project_id"], second["project_id"])
            plan = adaptive.load_or_create_plan(project, "Create app")
            plan.work_packets.append(self.packet())
            plan.active_packet_id = "packet-001"
            adaptive.save_plan(project, plan)
            loaded = adaptive.load_or_create_plan(project, "Create app")
            self.assertEqual(loaded.plan_id, plan.plan_id)
            self.assertEqual(loaded.active_packet_id, "packet-001")

    def test_goal_change_does_not_silently_replace_plan(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            plan = adaptive.load_or_create_plan(project, "Goal A")
            adaptive.save_plan(project, plan)
            with self.assertRaises(RuntimeError):
                adaptive.load_or_create_plan(project, "Goal B")

    def test_patch_cannot_complete_before_dependency(self):
        base = adaptive.ProjectPlan(
            plan_id="plan-1",
            project_id="project-1",
            goal_hash="g",
            spec_hash="s",
            created_at=adaptive.utc_now(),
            updated_at=adaptive.utc_now(),
            work_packets=[
                self.packet("packet-001"),
                self.packet("packet-002", dependencies=["packet-001"]),
            ],
        )
        patch = adaptive.PlanPatch(
            update_packets=[
                adaptive.PacketUpdate(
                    packet_id="packet-002",
                    status="completed",
                    justification="Claim complete",
                )
            ]
        )
        with self.assertRaises(ValueError):
            adaptive.apply_plan_patch(base, patch, checks_passed=True)

    def test_patch_cannot_weaken_acceptance_criteria(self):
        base = adaptive.ProjectPlan(
            plan_id="plan-1",
            project_id="project-1",
            goal_hash="g",
            spec_hash="s",
            created_at=adaptive.utc_now(),
            updated_at=adaptive.utc_now(),
            work_packets=[
                self.packet(
                    acceptance_criteria=["Feature works", "Tests pass"]
                )
            ],
        )
        patch = adaptive.PlanPatch(
            update_packets=[
                adaptive.PacketUpdate(
                    packet_id="packet-001",
                    acceptance_criteria=["Feature works"],
                    justification="Unsafe weakening",
                )
            ]
        )
        with self.assertRaises(ValueError):
            adaptive.apply_plan_patch(base, patch, checks_passed=True)

    def test_patch_requires_checks_to_complete_packet(self):
        base = adaptive.ProjectPlan(
            plan_id="plan-1",
            project_id="project-1",
            goal_hash="g",
            spec_hash="s",
            created_at=adaptive.utc_now(),
            updated_at=adaptive.utc_now(),
            work_packets=[self.packet()],
        )
        patch = adaptive.PlanPatch(
            update_packets=[
                adaptive.PacketUpdate(
                    packet_id="packet-001",
                    status="completed",
                    justification="Verified",
                )
            ]
        )
        with self.assertRaises(ValueError):
            adaptive.apply_plan_patch(base, patch, checks_passed=False)
        updated = adaptive.apply_plan_patch(base, patch, checks_passed=True)
        self.assertEqual(updated.completed_packet_ids, ["packet-001"])

    def test_dependency_ready_packet_uses_persistent_plan_order(self):
        first = self.packet("packet-001", status="completed")
        second = self.packet(
            "packet-002",
            dependencies=["packet-001"],
        )
        third = self.packet(
            "packet-003",
            dependencies=["packet-001"],
        )
        plan = adaptive.ProjectPlan(
            plan_id="plan-1",
            project_id="project-1",
            goal_hash="g",
            spec_hash="s",
            created_at=adaptive.utc_now(),
            updated_at=adaptive.utc_now(),
            work_packets=[first, second, third],
            completed_packet_ids=["packet-001"],
        )
        self.assertEqual(
            adaptive.dependency_ready_packet(plan).packet_id,
            "packet-002",
        )

    def test_green_lean_packet_is_closed_and_next_is_activated(self):
        first = self.packet(
            "packet-001",
            worker_prompt="Implement packet 1.",
            status="in_progress",
        )
        second = self.packet(
            "packet-002",
            worker_prompt="Implement packet 2.",
            dependencies=["packet-001"],
        )
        plan = adaptive.ProjectPlan(
            plan_id="plan-1",
            project_id="project-1",
            goal_hash="g",
            spec_hash="s",
            created_at=adaptive.utc_now(),
            updated_at=adaptive.utc_now(),
            status="active",
            active_packet_id="packet-001",
            work_packets=[first, second],
        )
        updated = forge.complete_lean_packet_by_checks(plan, "packet-001")
        self.assertEqual(updated.completed_packet_ids, ["packet-001"])
        self.assertEqual(updated.work_packets[0].completed_by, "forge_checks")
        self.assertEqual(updated.active_packet_id, "packet-002")
        self.assertEqual(updated.work_packets[1].status, "in_progress")

    def test_lean_packet_keeps_both_consecutive_check_failures_for_review(self):
        packet = self.packet(
            "packet-001",
            worker_prompt="Repair the packet.",
            status="in_progress",
        )
        plan = adaptive.ProjectPlan(
            plan_id="plan-1",
            project_id="project-1",
            goal_hash="g",
            spec_hash="s",
            created_at=adaptive.utc_now(),
            updated_at=adaptive.utc_now(),
            status="active",
            active_packet_id=packet.packet_id,
            work_packets=[packet],
        )
        first = forge.CheckResult(
            command="first",
            check_id="targeted",
            exit_code=1,
            output="first grounded failure",
        )
        second = forge.CheckResult(
            command="second",
            check_id="targeted",
            exit_code=1,
            output="second grounded failure",
        )
        plan = forge.record_lean_check_evidence(plan, packet.packet_id, [first])
        plan = forge.record_lean_check_evidence(plan, packet.packet_id, [second])
        history = plan.work_packets[0].consecutive_check_failures
        self.assertEqual(len(history), 2)
        prompt = forge.build_review_prompt(
            "Repair app",
            3,
            "repository evidence",
            None,
            [second],
            0,
            project_plan=plan,
            active_packet=plan.work_packets[0],
        )
        self.assertIn("first grounded failure", prompt)
        self.assertIn("second grounded failure", prompt)

    def test_claude_reviewer_rejection_allows_one_repair_then_codex(self):
        packet = self.packet(
            "packet-001",
            worker_prompt="Implement the milestone.",
            status="in_progress",
            check_tier="milestone",
            attempts=1,
        )
        plan = adaptive.ProjectPlan(
            plan_id="plan-1",
            project_id="project-1",
            goal_hash="g",
            spec_hash="s",
            created_at=adaptive.utc_now(),
            updated_at=adaptive.utc_now(),
            status="active",
            active_packet_id=packet.packet_id,
            work_packets=[packet],
        )
        verdict = forge.ClaudeReviewVerdict(
            approve=False,
            issues=[
                forge.ClaudeReviewIssue(
                    file_path="src/app.py",
                    description="Handle the empty state.",
                )
            ],
        )
        updated, repair = forge.prepare_claude_review_repair(
            plan,
            packet.packet_id,
            verdict,
        )
        self.assertIsNotNone(repair)
        self.assertIn("Handle the empty state", repair.next_prompt or "")
        self.assertEqual(updated.work_packets[0].attempts, 1)
        self.assertTrue(updated.work_packets[0].claude_review_repair_used)
        second, second_repair = forge.prepare_claude_review_repair(
            updated,
            packet.packet_id,
            verdict,
        )
        self.assertIsNone(second_repair)
        self.assertEqual(second.work_packets[0].attempts, 1)

    def test_second_review_issue_on_unchanged_file_is_late_without_attempt(self):
        packet = self.packet(
            "packet-001",
            worker_prompt="Repair the packet.",
            status="in_progress",
            attempts=2,
        )
        plan = adaptive.ProjectPlan(
            plan_id="plan-1",
            project_id="project-1",
            goal_hash="g",
            spec_hash="s",
            created_at=adaptive.utc_now(),
            updated_at=adaptive.utc_now(),
            status="active",
            active_packet_id=packet.packet_id,
            work_packets=[packet],
        )
        manifest = {"src/app.py": "same-sha256"}
        plan, first_late = forge.record_review_snapshot(
            plan,
            packet.packet_id,
            manifest=manifest,
            reviewed_paths=["src/app.py"],
            issues=[],
        )
        self.assertEqual(first_late, [])
        plan, second_late = forge.record_review_snapshot(
            plan,
            packet.packet_id,
            manifest=manifest,
            reviewed_paths=["src/app.py"],
            issues=[
                adaptive.ReviewIssue(
                    file_path="src/app.py",
                    description="Previously omitted grounded issue.",
                )
            ],
        )
        self.assertEqual(len(second_late), 1)
        self.assertEqual(
            second_late[0]["file_path"],
            "src/app.py",
        )
        self.assertEqual(plan.work_packets[0].attempts, 2)
        self.assertEqual(len(plan.work_packets[0].late_findings), 1)

    def test_normal_content_attempt_increments_and_technical_refund_restores_it(self):
        packet = self.packet(
            "packet-001",
            worker_prompt="Implement packet.",
            status="in_progress",
            attempts=0,
        )
        plan = adaptive.ProjectPlan(
            plan_id="plan-1",
            project_id="project-1",
            goal_hash="g",
            spec_hash="s",
            created_at=adaptive.utc_now(),
            updated_at=adaptive.utc_now(),
            status="active",
            active_packet_id=packet.packet_id,
            work_packets=[packet],
        )
        attempted, recovery = adaptive.begin_packet_attempt(
            plan,
            packet.packet_id,
            forge.DEFAULT_CONFIG,
        )
        self.assertFalse(recovery)
        self.assertEqual(attempted.work_packets[0].attempts, 1)
        refunded = adaptive.refund_packet_attempt(
            attempted,
            packet.packet_id,
            recovery_attempt=False,
        )
        self.assertEqual(refunded.work_packets[0].attempts, 0)

    def test_docs_scope_allows_docs_readme_and_explicit_paths_only(self):
        packet = self.packet(
            "packet-docs",
            packet_type="docs",
            worker_prompt="Update the documentation.",
            expected_paths=["CHANGELOG.md"],
        )
        before = {
            "docs/guide.md": "old",
            "README.md": "old",
            "CHANGELOG.md": "old",
            "src/app.py": "old",
        }
        allowed_after = {
            **before,
            "docs/guide.md": "new",
            "README.md": "new",
            "CHANGELOG.md": "new",
        }
        self.assertEqual(
            forge.lean_docs_scope_violations(packet, before, allowed_after),
            [],
        )
        forbidden_after = {**allowed_after, "src/app.py": "new"}
        self.assertEqual(
            forge.lean_docs_scope_violations(packet, before, forbidden_after),
            ["src/app.py"],
        )

    def test_replan_preserves_completed_packets_and_safe_assumptions(self):
        completed = self.packet("packet-001", status="completed")
        pending = self.packet(
            "packet-002",
            dependencies=["packet-001"],
        )
        base = adaptive.ProjectPlan(
            plan_id="plan-1",
            project_id="project-1",
            goal_hash="g",
            spec_hash="s",
            created_at=adaptive.utc_now(),
            updated_at=adaptive.utc_now(),
            work_packets=[completed, pending],
            completed_packet_ids=["packet-001"],
            safe_assumptions=["Use a local offline database."],
        )
        patch = adaptive.PlanPatch(
            active_packet_id="packet-002",
            append_safe_assumptions=["Prefer a reversible MVP."],
            explanation="Continue with the next dependency-ready packet.",
        )
        updated = adaptive.apply_plan_patch(base, patch, checks_passed=True)
        self.assertEqual(updated.completed_packet_ids, ["packet-001"])
        self.assertEqual(updated.work_packets[0].status, "completed")
        self.assertEqual(updated.active_packet_id, "packet-002")
        self.assertEqual(
            updated.safe_assumptions,
            ["Use a local offline database.", "Prefer a reversible MVP."],
        )
        with tempfile.TemporaryDirectory() as temp:
            assumptions = adaptive.write_assumptions(
                Path(temp), updated.safe_assumptions
            ).read_text(encoding="utf-8")
        self.assertIn("Use a local offline database.", assumptions)
        self.assertIn("Prefer a reversible MVP.", assumptions)

    def test_blocking_only_reachable_packet_derives_blocked_plan(self):
        base = adaptive.ProjectPlan(
            plan_id="plan-1",
            project_id="project-1",
            goal_hash="g",
            spec_hash="s",
            created_at=adaptive.utc_now(),
            updated_at=adaptive.utc_now(),
            status="active",
            active_packet_id="packet-001",
            work_packets=[
                self.packet("packet-001", status="in_progress"),
                self.packet("packet-002", dependencies=["packet-001"]),
            ],
        )
        patch = adaptive.PlanPatch(
            update_packets=[
                adaptive.PacketUpdate(
                    packet_id="packet-001",
                    status="blocked",
                    justification="A required external account is unavailable.",
                )
            ],
            explanation="Persist the real dependency blocker.",
        )

        updated = adaptive.apply_plan_patch(base, patch, checks_passed=False)

        self.assertEqual(updated.status, "blocked")
        self.assertEqual(updated.work_packets[0].status, "blocked")

    def test_blocked_packet_does_not_hide_independent_ready_work(self):
        base = adaptive.ProjectPlan(
            plan_id="plan-1",
            project_id="project-1",
            goal_hash="g",
            spec_hash="s",
            created_at=adaptive.utc_now(),
            updated_at=adaptive.utc_now(),
            status="active",
            active_packet_id="packet-001",
            work_packets=[
                self.packet("packet-001", status="in_progress"),
                self.packet("packet-002"),
            ],
        )
        patch = adaptive.PlanPatch(
            update_packets=[
                adaptive.PacketUpdate(
                    packet_id="packet-001",
                    status="blocked",
                    justification="Only this external integration is blocked.",
                )
            ],
            explanation="Continue independent local work.",
        )

        updated = adaptive.apply_plan_patch(base, patch, checks_passed=False)

        self.assertEqual(updated.status, "active")
        self.assertEqual(updated.active_packet_id, "packet-002")
        self.assertEqual(updated.work_packets[1].status, "in_progress")


class AdaptiveRouterTests(unittest.TestCase):
    def packet(self, **overrides):
        payload = {
            "packet_id": "packet-001",
            "title": "Routine UI",
            "objective": "Add list screen.",
            "acceptance_criteria": ["Screen works"],
        }
        payload.update(overrides)
        return adaptive.WorkPacket(**payload)

    def profiles(self):
        return {
            "adaptive_profiles": {
                "claude": {
                    "economy": {
                        "max_turns": 8,
                        "reason": "Low-risk mechanical work.",
                        "candidates": [{"model": "sonnet", "effort": "low"}],
                    },
                    "frontier": {
                        "max_turns": 30,
                        "reason": "Exceptional work.",
                        "candidates": [
                            {
                                "model": "fable",
                                "effort": "high",
                                "requires_subscription_confirmation": True,
                            },
                            {"model": "opus", "effort": "high"},
                            {"model": "sonnet", "effort": "high"},
                        ],
                    },
                }
            },
            "confirmed_subscription_models": [],
            "claude_supports_model": True,
            "claude_supports_effort": True,
            "claude_supports_max_turns": False,
        }

    def test_economy_rejected_for_authentication(self):
        packet = self.packet(objective="Change authentication and authorization")
        profile, reason = adaptive.choose_worker_profile(
            packet,
            "economy",
            no_progress_count=0,
            repeated_failure_count=0,
            checks_failed=False,
        )
        self.assertEqual(profile, "complex")
        self.assertIn("rejected", reason)

    def test_mechanical_low_risk_packet_uses_economy(self):
        packet = self.packet(difficulty="mechanical", risk="low")
        profile, _ = adaptive.choose_worker_profile(
            packet,
            "standard",
            no_progress_count=0,
            repeated_failure_count=0,
            checks_failed=False,
        )
        self.assertEqual(profile, "economy")

    def test_routine_packet_uses_standard(self):
        profile, _ = adaptive.choose_worker_profile(
            self.packet(difficulty="routine", risk="medium"),
            "economy",
            no_progress_count=0,
            repeated_failure_count=0,
            checks_failed=False,
        )
        self.assertEqual(profile, "standard")

    def test_complex_database_packet_uses_complex(self):
        profile, _ = adaptive.choose_worker_profile(
            self.packet(
                title="Database transaction",
                objective="Implement a multi-layer database transaction.",
                difficulty="complex",
                risk="high",
                recommended_worker_profile="complex",
                check_tier="milestone",
            ),
            "standard",
            no_progress_count=0,
            repeated_failure_count=0,
            checks_failed=False,
        )
        self.assertEqual(profile, "complex")

    def test_simple_packet_cannot_force_frontier(self):
        profile, _ = adaptive.choose_worker_profile(
            self.packet(),
            "frontier",
            no_progress_count=0,
            repeated_failure_count=0,
            checks_failed=False,
        )
        self.assertEqual(profile, "complex")

    def test_rescue_requires_measured_stuck_condition(self):
        packet = self.packet(recommended_worker_profile="rescue")
        profile, _ = adaptive.choose_worker_profile(
            packet,
            "rescue",
            no_progress_count=0,
            repeated_failure_count=0,
            checks_failed=False,
        )
        self.assertEqual(profile, "complex")
        profile, _ = adaptive.choose_worker_profile(
            packet,
            "rescue",
            no_progress_count=1,
            repeated_failure_count=0,
            checks_failed=False,
        )
        self.assertEqual(profile, "rescue")

    def test_frontier_skips_unconfirmed_fable_without_credits(self):
        routing = adaptive.resolve_worker_runtime("frontier", self.profiles())
        self.assertEqual(routing.selected_model, "opus")
        self.assertEqual(routing.fallback_from, "fable")
        self.assertFalse(routing.max_turns_argument_allowed)

    def test_router_falls_back_from_unavailable_model(self):
        routing = adaptive.resolve_worker_runtime(
            "frontier", self.profiles(), unsupported_models={"opus"}
        )
        self.assertEqual(routing.selected_model, "sonnet")

    def test_routine_packet_uses_routine_codex_review(self):
        profile, _ = adaptive.choose_codex_profile(
            phase="review",
            packet=self.packet(),
            repeated_failure_count=0,
            milestone=False,
        )
        self.assertEqual(profile, "routine_review")

    def test_high_risk_packet_uses_important_codex_review(self):
        profile, _ = adaptive.choose_codex_profile(
            phase="review",
            packet=self.packet(
                difficulty="complex",
                risk="high",
                recommended_worker_profile="complex",
                check_tier="milestone",
            ),
            repeated_failure_count=0,
            milestone=False,
        )
        self.assertEqual(profile, "important_review")

    def test_final_review_profile_is_always_strong(self):
        profile, _ = adaptive.choose_codex_profile(
            phase="final",
            packet=self.packet(),
            repeated_failure_count=0,
            milestone=False,
        )
        self.assertEqual(profile, "final_review")

    def test_unknown_profile_is_not_allowlisted(self):
        with self.assertRaises(RuntimeError):
            adaptive.resolve_worker_runtime("invented-premium", self.profiles())


class AdaptiveChecksAndEvidenceTests(unittest.TestCase):
    def config(self):
        return {
            "check_definitions": [
                {
                    "check_id": "diff",
                    "command": "git diff --check",
                    "tier": "smoke",
                },
                {
                    "check_id": "unit",
                    "command": "python -m unittest",
                    "tier": "targeted",
                    "test_count_pattern": "Ran (?P<count>\\d+) tests?",
                },
                {
                    "check_id": "build",
                    "command": "npm run build",
                    "tier": "release",
                    "required_before_done": True,
                },
            ]
        }

    def test_check_tiers_select_only_allowlisted_commands(self):
        targeted = adaptive.select_check_definitions(self.config(), "targeted")
        self.assertEqual([item.check_id for item in targeted], ["diff", "unit"])
        release = adaptive.select_check_definitions(self.config(), "release")
        self.assertEqual([item.check_id for item in release], ["diff", "unit", "build"])
        with self.assertRaises(ValueError):
            adaptive.select_check_definitions(
                self.config(), "targeted", requested_ids=["invented-shell"]
            )

    def test_unsafe_check_command_is_rejected(self):
        commands = [
            "git push origin main",
            "npm publish",
            "vercel deploy --prod",
            "firebase deploy",
            "gh release create v1.0.0",
        ]
        for index, command in enumerate(commands):
            with self.subTest(command=command), self.assertRaises(ValidationError):
                adaptive.CheckDefinition(
                    check_id=f"unsafe-{index}",
                    command=command,
                    tier="release",
                )

    def test_release_check_cannot_be_cached(self):
        with self.assertRaises(ValidationError):
            adaptive.CheckDefinition(
                check_id="release",
                command="npm run build",
                tier="release",
                cacheable=True,
            )

    def test_security_check_cannot_be_cached(self):
        with self.assertRaises(ValidationError):
            adaptive.CheckDefinition(
                check_id="security-audit",
                command="python -m bandit -r src",
                tier="milestone",
                cacheable=True,
            )

    def test_test_count_and_report_validation(self):
        definition = adaptive.normalize_check_definitions(self.config())[1]
        self.assertEqual(adaptive.detect_test_count("Ran 36 tests in 2s", definition), 36)

    def test_zero_exit_without_expected_test_count_is_not_green(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            config = forge.DEFAULT_CONFIG.copy()
            config.update(
                {
                    "adaptive_orchestration": True,
                    "auto_detect_checks": False,
                    "sandbox_checks": "off",
                    "check_definitions": [
                        {
                            "check_id": "fake-tests",
                            "command": (
                                f'"{__import__("sys").executable}" '
                                '-c "print(\'No tests collected\')"'
                            ),
                            "tier": "targeted",
                            "timeout_seconds": 30,
                            "test_count_pattern": "Ran (?P<count>\\d+) tests?",
                        }
                    ],
                }
            )
            results = forge.run_checks(project, config, tier="targeted")
        self.assertEqual(results[0].exit_code, 0)
        self.assertIsNone(results[0].test_count)
        self.assertFalse(results[0].report_valid)
        self.assertFalse(forge.checks_passed(results))

    def test_cache_key_changes_with_lockfile_or_toolchain(self):
        definition = adaptive.CheckDefinition(
            check_id="unit", command="python -m unittest", cacheable=True
        )
        common = {
            "definition": definition,
            "input_hashes": {"a.py": "1"},
            "environment_fingerprint": "env",
            "config_hash": "cfg",
            "generated_source_hashes": {},
            "external_change_fingerprint": "external",
        }
        first = adaptive.check_cache_key(
            **common,
            lockfile_hashes={"lock": "1"},
            toolchain_versions={"python": "3.12"},
        )
        second = adaptive.check_cache_key(
            **common,
            lockfile_hashes={"lock": "2"},
            toolchain_versions={"python": "3.12"},
        )
        self.assertNotEqual(first, second)

    def test_evidence_index_omits_success_output(self):
        evidence = adaptive.build_evidence_index(
            before_manifest={"a.py": "1"},
            after_manifest={"a.py": "2", "auth.py": "3"},
            repository_fingerprint="fp",
            diff_text="@@ -1 +1 @@\n-old\n+new",
            checks=[
                {"check_id": "unit", "exit_code": 0, "output": "very long success"},
                {"check_id": "lint", "exit_code": 1, "output": "failure detail"},
            ],
        )
        serialized = evidence.model_dump_json()
        self.assertNotIn("very long success", serialized)
        self.assertIn("failure detail", serialized)
        self.assertIn("auth.py", evidence.risk_areas)


class ChainBudgetTests(unittest.TestCase):
    def test_every_hard_budget_has_a_terminal_reason(self):
        budgets = adaptive.ChainBudgets(
            max_child_runs=2,
            max_codex_calls=3,
            max_worker_calls=4,
            max_elapsed_seconds=60,
            max_full_check_suites=2,
            max_premium_escalations=1,
            max_no_progress_events=2,
        )
        cases = [
            adaptive.ChainCounters(child_runs=2),
            adaptive.ChainCounters(codex_calls=3),
            adaptive.ChainCounters(worker_calls=4),
            adaptive.ChainCounters(elapsed_seconds=60),
            adaptive.ChainCounters(full_check_suites=2),
            adaptive.ChainCounters(premium_escalations=1),
            adaptive.ChainCounters(no_progress_events=2),
        ]
        for counters in cases:
            with self.subTest(counters=counters):
                self.assertIn(
                    "budget exhausted",
                    adaptive.budget_exhaustion(counters, budgets),
                )

    def test_elapsed_and_no_progress_limits_are_terminal(self):
        budgets = adaptive.ChainBudgets(
            max_elapsed_seconds=60,
            max_no_progress_events=2,
        )
        self.assertIn(
            "elapsed seconds",
            adaptive.budget_exhaustion(
                adaptive.ChainCounters(elapsed_seconds=60),
                budgets,
            ),
        )
        self.assertIn(
            "no-progress events",
            adaptive.budget_exhaustion(
                adaptive.ChainCounters(no_progress_events=2),
                budgets,
            ),
        )

    def test_schema_export_is_valid_json(self):
        with tempfile.TemporaryDirectory() as temp:
            paths = adaptive.export_schemas(Path(temp))
            self.assertGreaterEqual(len(paths), 7)
            for path in paths:
                json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
