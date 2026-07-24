import json
import os
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import forge
import forge_adaptive as adaptive
from forge_reports import evaluate_test_evidence


def worker(
    model: str,
    reason: str = "success",
    *,
    exit_code: int | None = None,
) -> forge.WorkerResult:
    return forge.WorkerResult(
        exit_code=(0 if reason == "success" else 1)
        if exit_code is None
        else exit_code,
        summary=reason,
        raw_output=reason,
        duration_seconds=0.01,
        model=model,
        effort="low",
        termination_reason=reason,
    )


class RouterAndFallbackRequirements(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.project = Path(self.temp.name) / "project"
        self.project.mkdir()
        self.logs = self.project / "logs"
        self.logs.mkdir()
        self.decision = forge.Decision(
            status="continue",
            assessment="Implement packet.",
            next_prompt="Implement the exact packet.",
            acceptance_criteria=["Packet passes"],
        )

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def config() -> dict:
        config = forge.DEFAULT_CONFIG.copy()
        config.update(
            {
                "claude_timeout_seconds": 30,
                "max_packet_attempts": 3,
                "confirmed_subscription_models": ["fable", "haiku"],
                "adaptive_profiles": {
                    "claude": {
                        "economy": {
                            "max_turns": 8,
                            "candidates": [
                                {
                                    "model": "haiku",
                                    "effort": "low",
                                    "requires_subscription_confirmation": True,
                                },
                                {"model": "sonnet", "effort": "low"},
                            ],
                        },
                        "standard": {
                            "max_turns": 20,
                            "candidates": [
                                {"model": "model-a", "effort": "medium"},
                                {"model": "model-b", "effort": "medium"},
                            ],
                        },
                        "complex": {
                            "max_turns": 30,
                            "candidates": [{"model": "sonnet", "effort": "high"}],
                        },
                        "frontier": {
                            "max_turns": 35,
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
                        "rescue": {
                            "max_turns": 30,
                            "candidates": [
                                {"model": "opus", "effort": "high"},
                                {"model": "sonnet", "effort": "high"},
                            ],
                        },
                    }
                },
            }
        )
        return config

    def routed(self, profile: str, side_effect, **kwargs):
        with mock.patch.object(forge, "run_claude", side_effect=side_effect):
            return forge.run_claude_routed(
                self.project,
                "Goal",
                self.decision,
                self.config(),
                profile=profile,
                routing_reason="test",
                iteration=1,
                logs=self.logs,
                max_worker_calls_remaining=kwargs.get("max_calls", 8),
                max_premium_calls_remaining=kwargs.get("max_premium", 1),
                unavailable_models=kwargs.get("unavailable"),
            )

    def test_01_every_production_claude_call_uses_common_router(self):
        source = Path(forge.__file__).read_text(encoding="utf-8")
        calls = [
            match.start()
            for match in re.finditer(r"(?<!def )run_claude\(", source)
        ]
        self.assertEqual(len(calls), 1)
        self.assertIn("def run_claude_routed(", source)

    def test_02_legacy_escalation_cannot_hardcode_opus(self):
        source = Path(forge.__file__).read_text(encoding="utf-8")
        self.assertNotIn(
            'model_override=str(config.get("claude_escalation_model")', source
        )
        self.assertIn('profile="rescue"', source)

    def test_03_stuck_state_selects_rescue(self):
        packet = adaptive.WorkPacket(
            packet_id="p", title="Repair", objective="Repair", acceptance_criteria=["ok"]
        )
        profile, _ = adaptive.choose_worker_profile(
            packet,
            "rescue",
            no_progress_count=1,
            repeated_failure_count=0,
            checks_failed=False,
        )
        self.assertEqual(profile, "rescue")

    def test_04_rescue_respects_premium_chain_budget(self):
        outcome = self.routed(
            "rescue", [worker("sonnet")], max_premium=0
        )
        self.assertEqual(outcome.worker.model, "sonnet")
        self.assertEqual(outcome.premium_calls, 0)

    def test_05_simple_packet_cannot_force_rescue_or_frontier(self):
        packet = adaptive.WorkPacket(
            packet_id="p", title="Text", objective="Text", acceptance_criteria=["ok"]
        )
        rescue, _ = adaptive.choose_worker_profile(
            packet, "rescue", no_progress_count=0, repeated_failure_count=0,
            checks_failed=False
        )
        frontier, _ = adaptive.choose_worker_profile(
            packet, "frontier", no_progress_count=0, repeated_failure_count=0,
            checks_failed=False
        )
        self.assertEqual((rescue, frontier), ("complex", "complex"))

    def test_06_high_risk_packet_cannot_use_economy(self):
        packet = adaptive.WorkPacket(
            packet_id="p", title="Payment", objective="Payment authorization",
            acceptance_criteria=["ok"], risk="high"
        )
        profile, _ = adaptive.choose_worker_profile(
            packet, "economy", no_progress_count=0, repeated_failure_count=0,
            checks_failed=False
        )
        self.assertEqual(profile, "complex")

    def test_07_fable_unavailable_falls_back_to_opus(self):
        outcome = self.routed(
            "frontier",
            [worker("fable", "model_unavailable"), worker("opus")],
        )
        self.assertEqual(outcome.worker.model, "opus")
        self.assertEqual(outcome.model_fallbacks, 1)

    def test_08_opus_unavailable_falls_back_to_sonnet(self):
        outcome = self.routed(
            "frontier",
            [worker("opus", "model_unavailable"), worker("sonnet")],
            unavailable={"fable": "model_unavailable"},
        )
        self.assertEqual(outcome.worker.model, "sonnet")

    def test_09_model_not_included_falls_back(self):
        outcome = self.routed(
            "standard",
            [worker("model-a", "model_not_included"), worker("model-b")],
        )
        self.assertEqual(outcome.worker.model, "model-b")

    def test_10_usage_credits_required_never_enables_api_or_purchase(self):
        seen = []

        def fake(*args, **kwargs):
            seen.append(kwargs["model_override"])
            return (
                worker("model-a", "usage_credits_required")
                if len(seen) == 1
                else worker("model-b")
            )

        outcome = self.routed("standard", fake)
        self.assertEqual(outcome.worker.model, "model-b")
        self.assertEqual(seen, ["model-a", "model-b"])
        self.assertNotIn("api", " ".join(seen).casefold())

    def test_11_all_candidates_unavailable_end_safely(self):
        outcome = self.routed(
            "standard",
            [
                worker("model-a", "model_unavailable"),
                worker("model-b", "model_unavailable"),
            ],
        )
        self.assertEqual(
            outcome.worker.termination_reason,
            "model_unavailable_without_credits",
        )

    def test_12_auth_failure_is_not_a_model_fallback(self):
        outcome = self.routed("standard", [worker("model-a", "auth_failure")])
        self.assertEqual(outcome.worker_calls, 1)
        self.assertEqual(outcome.model_fallbacks, 0)

    def test_13_subscription_limit_is_not_a_model_fallback(self):
        error = forge.SubscriptionLimitError(
            "limit", worker("model-a", "subscription_limit")
        )
        with self.assertRaises(forge.SubscriptionLimitError):
            self.routed("standard", error)

    def test_14_timeout_is_not_model_unavailable(self):
        outcome = self.routed("standard", [worker("model-a", "timeout", exit_code=124)])
        self.assertEqual(outcome.worker_calls, 1)
        self.assertEqual(outcome.worker.termination_reason, "timeout")

    def test_15_exact_decision_is_preserved_during_fallback(self):
        seen = []

        def fake(project, goal, decision, config, **kwargs):
            seen.append((id(decision), decision.next_prompt))
            return (
                worker("model-a", "model_unavailable")
                if len(seen) == 1
                else worker("model-b")
            )

        self.routed("standard", fake)
        self.assertEqual(seen, [(id(self.decision), self.decision.next_prompt)] * 2)

    def test_16_fallback_worker_counters_do_not_reset(self):
        outcome = self.routed(
            "standard",
            [worker("model-a", "model_unavailable"), worker("model-b")],
        )
        self.assertEqual(outcome.worker_calls, 2)
        self.assertEqual(outcome.model_fallbacks, 1)

    def test_17_routing_record_contains_fallback_reason(self):
        outcome = self.routed(
            "standard",
            [worker("model-a", "model_unavailable"), worker("model-b")],
        )
        self.assertEqual(
            outcome.routing_records[-1]["fallback_reason"], "model_unavailable"
        )

    def test_18_economy_uses_confirmed_cheaper_model(self):
        route = adaptive.resolve_worker_runtime("economy", self.config())
        self.assertEqual((route.selected_model, route.selected_effort), ("haiku", "low"))

    def test_19_unconfirmed_cheaper_model_falls_back_to_sonnet_low(self):
        config = self.config()
        config["confirmed_subscription_models"] = []
        route = adaptive.resolve_worker_runtime("economy", config)
        self.assertEqual((route.selected_model, route.selected_effort), ("sonnet", "low"))
        self.assertEqual(route.fallback_reason, "subscription_not_confirmed")

    def test_20_economy_rejected_for_authentication_and_payment(self):
        for objective in ("Change authentication", "Implement payment"):
            packet = adaptive.WorkPacket(
                packet_id="p", title=objective, objective=objective,
                acceptance_criteria=["ok"], difficulty="mechanical", risk="low"
            )
            profile, _ = adaptive.choose_worker_profile(
                packet, "economy", no_progress_count=0,
                repeated_failure_count=0, checks_failed=False
            )
            self.assertEqual(profile, "complex")

    def test_21_economy_fallback_has_no_api_candidate(self):
        config = self.config()
        config["confirmed_subscription_models"] = []
        candidates = config["adaptive_profiles"]["claude"]["economy"]["candidates"]
        self.assertFalse(any("api" in str(item).casefold() for item in candidates))

    def test_22_supported_max_turns_is_truthfully_enforced(self):
        config = self.config()
        config["claude_supports_max_turns"] = True
        route = adaptive.resolve_worker_runtime("standard", config)
        self.assertTrue(route.cli_turn_limit_enforced)
        self.assertEqual(route.requested_turn_budget, 20)

    def test_23_unsupported_max_turns_is_not_claimed(self):
        config = self.config()
        config["claude_supports_max_turns"] = False
        route = adaptive.resolve_worker_runtime("standard", config)
        self.assertFalse(route.cli_turn_limit_enforced)
        self.assertFalse(route.max_turns_argument_allowed)

    def test_24_routing_telemetry_contains_truthful_turn_fields(self):
        route = adaptive.resolve_worker_runtime("standard", self.config())
        data = route.model_dump()
        for key in (
            "requested_turn_budget", "cli_turn_limit_enforced",
            "effective_timeout", "max_packet_attempts", "max_chain_worker_calls"
        ):
            self.assertIn(key, data)

    def test_25_packet_attempt_limit_stops_repeated_worker(self):
        packet = adaptive.WorkPacket(
            packet_id="p", title="P", objective="P", acceptance_criteria=["ok"],
            attempts=3
        )
        self.assertTrue(
            adaptive.packet_attempt_budget_exhausted(
                packet, {"max_packet_attempts": 3}
            )
        )

    def test_26_worker_timeout_has_distinct_termination_reason(self):
        reason = adaptive.classify_worker_termination(
            "model unavailable", exit_code=124, timed_out=True
        )
        self.assertEqual(reason, "timeout")

    def test_27_continuation_preserves_chain_fallback_counters(self):
        payload = forge.ContinuationPayload(
            source_run_id="run",
            continuation_chain_id="chain",
            next_prompt="continue",
            repository_fingerprint="hash",
            chain_worker_calls=5,
            chain_model_fallbacks=2,
            unavailable_models={"fable": "model_unavailable"},
        )
        restored = forge.ContinuationPayload.model_validate(payload.model_dump())
        self.assertEqual(restored.chain_worker_calls, 5)
        self.assertEqual(restored.chain_model_fallbacks, 2)


class TestReportAdapterRequirements(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.project = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def definition(self, **overrides):
        payload = {
            "check_id": "tests",
            "command": "run tests",
            "check_kind": "test",
            "require_test_execution": True,
        }
        payload.update(overrides)
        return adaptive.CheckDefinition(**payload)

    def write(self, name, content):
        path = self.project / name
        path.write_text(content, encoding="utf-8")
        return path

    def evaluate(self, definition, output=""):
        return evaluate_test_evidence(
            self.project, definition, output, started_wall_time=time.time() - 0.2
        )

    def test_28_pytest_text_report(self):
        metrics = self.evaluate(
            self.definition(report_format="pytest-text"),
            "collected 4 items\n3 passed, 1 skipped",
        )
        self.assertEqual((metrics.discovered, metrics.executed), (4, 3))
        self.assertTrue(metrics.report_valid)

    def test_29_junit_xml_report(self):
        self.write(
            "pytest.xml",
            '<testsuite tests="4" failures="1" errors="0" skipped="1"/>',
        )
        metrics = self.evaluate(
            self.definition(report_path="pytest.xml", report_format="junit-xml")
        )
        self.assertEqual((metrics.passed, metrics.failed, metrics.skipped), (2, 1, 1))

    def test_30_jest_and_vitest_json_reports(self):
        for name, fmt in (("jest.json", "jest-json"), ("vitest.json", "vitest-json")):
            self.write(
                name,
                json.dumps(
                    {
                        "numTotalTests": 5,
                        "numPassedTests": 4,
                        "numFailedTests": 0,
                        "numPendingTests": 1,
                    }
                ),
            )
            metrics = self.evaluate(
                self.definition(report_path=name, report_format=fmt)
            )
            self.assertEqual((metrics.discovered, metrics.executed), (5, 4))

    def test_31_playwright_json_report(self):
        self.write(
            "playwright.json",
            json.dumps(
                {"stats": {"expected": 2, "unexpected": 0, "skipped": 1, "flaky": 0}}
            ),
        )
        metrics = self.evaluate(
            self.definition(
                report_path="playwright.json", report_format="playwright-json"
            )
        )
        self.assertEqual((metrics.discovered, metrics.executed), (3, 2))

    def test_32_gradle_and_android_junit_reports(self):
        xml = '<testsuite tests="3" failures="0" skipped="1"/>'
        for name, fmt in (
            ("gradle.xml", "gradle-junit"),
            ("android.xml", "android-junit"),
        ):
            self.write(name, xml)
            metrics = self.evaluate(
                self.definition(report_path=name, report_format=fmt)
            )
            self.assertEqual((metrics.passed, metrics.skipped), (2, 1))

    def test_33_trx_report(self):
        self.write(
            "results.trx",
            '<TestRun><ResultSummary><Counters total="4" executed="3" '
            'passed="3" failed="0"/></ResultSummary></TestRun>',
        )
        metrics = self.evaluate(
            self.definition(report_path="results.trx", report_format="trx")
        )
        self.assertEqual((metrics.discovered, metrics.executed), (4, 3))

    def test_34_exit_zero_with_zero_tests_is_invalid(self):
        metrics = self.evaluate(
            self.definition(report_format="pytest-text"), "collected 0 items"
        )
        self.assertFalse(metrics.report_valid)

    def test_35_build_without_test_count_can_pass(self):
        definition = adaptive.CheckDefinition(
            check_id="build", command="npm run build", check_kind="build"
        )
        metrics = self.evaluate(definition, "build complete")
        self.assertTrue(metrics.report_valid)
        self.assertIsNone(metrics.executed)

    def test_36_malformed_report_blocks_release(self):
        self.write("bad.xml", "<testsuite")
        metrics = self.evaluate(
            self.definition(report_path="bad.xml", report_format="junit-xml")
        )
        self.assertFalse(metrics.report_valid)

    def test_37_report_outside_project_is_rejected(self):
        outside = self.project.parent / "outside.xml"
        outside.write_text('<testsuite tests="1"/>', encoding="utf-8")
        metrics = self.evaluate(
            self.definition(report_path="../outside.xml", report_format="junit-xml")
        )
        self.assertFalse(metrics.report_valid)
        self.assertIn("escapes", metrics.failure_reason)

    def test_38_stale_report_is_rejected(self):
        path = self.write("stale.xml", '<testsuite tests="1"/>')
        old = time.time() - 120
        os.utime(path, (old, old))
        metrics = evaluate_test_evidence(
            self.project,
            self.definition(report_path="stale.xml", report_format="junit-xml"),
            "",
            started_wall_time=time.time(),
        )
        self.assertFalse(metrics.report_valid)
        self.assertIn("stale", metrics.failure_reason)


class DependencyGraphRequirements(unittest.TestCase):
    def packet(self, packet_id, dependencies=None, status="pending"):
        return adaptive.WorkPacket(
            packet_id=packet_id,
            title=packet_id,
            objective=packet_id,
            dependencies=dependencies or [],
            acceptance_criteria=["ok"],
            status=status,
        )

    def plan(self, packets, **overrides):
        payload = {
            "plan_id": "plan",
            "project_id": "project",
            "goal_hash": "goal",
            "spec_hash": "spec",
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
            "work_packets": packets,
        }
        payload.update(overrides)
        return adaptive.ProjectPlan(**payload)

    def test_39_two_node_cycle_is_rejected(self):
        with self.assertRaisesRegex(ValueError, r"A -> B -> A"):
            self.plan([self.packet("A", ["B"]), self.packet("B", ["A"])])

    def test_40_three_node_cycle_is_rejected(self):
        with self.assertRaisesRegex(ValueError, r"A -> B -> C -> A"):
            self.plan(
                [
                    self.packet("A", ["B"]),
                    self.packet("B", ["C"]),
                    self.packet("C", ["A"]),
                ]
            )

    def test_41_valid_dag_passes(self):
        plan = self.plan(
            [
                self.packet("A"),
                self.packet("B", ["A"]),
                self.packet("C", ["B"]),
            ]
        )
        self.assertEqual(len(plan.work_packets), 3)

    def test_42_cycle_created_by_plan_patch_is_rejected(self):
        plan = self.plan([self.packet("A"), self.packet("B", ["A"])])
        patch = adaptive.PlanPatch(
            update_packets=[
                adaptive.PacketUpdate(
                    packet_id="A",
                    dependencies=["B"],
                    justification="invalid cycle test",
                )
            ]
        )
        with self.assertRaisesRegex(ValueError, "cycle"):
            adaptive.apply_plan_patch(plan, patch, checks_passed=False)

    def test_43_plan_without_ready_packet_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no dependency-ready packet"):
            self.plan(
                [self.packet("A", status="blocked")],
                status="active",
            )

    def test_44_completed_plan_without_pending_packet_passes(self):
        plan = self.plan(
            [self.packet("A", status="completed")],
            status="done",
            completed_packet_ids=["A"],
        )
        self.assertEqual(plan.status, "done")


class EndToEndSafetyRequirements(unittest.TestCase):
    def test_45_multi_packet_fake_e2e_has_required_release_contract(self):
        source = (
            Path(__file__).with_name("test_adaptive_runtime.py")
            .read_text(encoding="utf-8")
        )
        self.assertIn("test_complete_fake_cli_multi_packet_chain_reaches_done", source)
        self.assertIn('"release"', source)
        self.assertIn('"economy"', source)
        self.assertIn('"complex"', Path(forge.__file__).read_text(encoding="utf-8"))

    def test_46_all_premium_models_unavailable_never_uses_api(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            logs = project / "logs"
            logs.mkdir()
            config = forge.DEFAULT_CONFIG.copy()
            config["adaptive_profiles"] = {
                "claude": {
                    "rescue": {
                        "max_turns": 20,
                        "candidates": [
                            {"model": "opus", "effort": "high"},
                            {"model": "fable", "effort": "high"},
                        ],
                    }
                }
            }
            decision = forge.Decision(
                status="continue", assessment="rescue", next_prompt="repair"
            )
            with mock.patch.object(
                forge,
                "run_claude",
                side_effect=[
                    worker("opus", "model_unavailable"),
                    worker("fable", "usage_credits_required"),
                ],
            ):
                outcome = forge.run_claude_routed(
                    project,
                    "goal",
                    decision,
                    config,
                    profile="rescue",
                    routing_reason="test",
                    iteration=1,
                    logs=logs,
                    max_worker_calls_remaining=3,
                    max_premium_calls_remaining=2,
                )
        self.assertEqual(
            outcome.worker.termination_reason,
            "model_unavailable_without_credits",
        )
        self.assertFalse(
            any("api" in record["selected_model"].casefold()
                for record in outcome.routing_records)
        )


if __name__ == "__main__":
    unittest.main()
