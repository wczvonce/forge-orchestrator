from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import forge


class SupervisorFailClosedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.strict_config = Path(forge.__file__).with_name(
            "forge.strict.config.json"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def assert_failed_supervisor(self, exit_code: int) -> dict:
        self.assertEqual(exit_code, forge.EXIT_FAILED)
        state = json.loads(
            (self.project / ".forge" / "chain-supervisor.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["exit_code"], forge.EXIT_FAILED)
        self.assertEqual(state["stop_reason_code"], "technical_failure")
        self.assertFalse(state["automatic_resume_allowed"])
        self.assertFalse(state["needs_human"])
        self.assertIn("finished_at", state)
        self.assertIn("elapsed_seconds", state)
        self.assertNotEqual(state["status"], "running")
        return state

    def test_config_validation_exception_terminalizes_supervisor(self) -> None:
        invalid_config = json.loads(
            self.strict_config.read_text(encoding="utf-8")
        )
        invalid_config["max_iterations"] = 0
        config_path = self.root / "invalid-config.json"
        config_path.write_text(json.dumps(invalid_config), encoding="utf-8")

        with mock.patch.object(
            forge,
            "sandbox_runtime_available",
            return_value=True,
        ):
            exit_code = forge.run_chain(
                self.project,
                "No model call.",
                config_path,
            )

        state = self.assert_failed_supervisor(exit_code)
        self.assertIn("max_iterations", state["stop_reason"])

    def test_non_object_config_system_exit_terminalizes_supervisor(self) -> None:
        config_path = self.root / "non-object-config.json"
        config_path.write_text("[]", encoding="utf-8")

        exit_code = forge.run_chain(
            self.project,
            "No model call.",
            config_path,
        )

        state = self.assert_failed_supervisor(exit_code)
        self.assertIn("SystemExit", state["stop_reason"])

    def test_unexpected_result_validation_exception_terminalizes_supervisor(
        self,
    ) -> None:
        with mock.patch.object(
            forge,
            "sandbox_runtime_available",
            return_value=True,
        ), mock.patch.object(
            forge,
            "run_forge",
            return_value=forge.EXIT_NEEDS_CONTINUATION,
        ), mock.patch.object(
            forge,
            "read_result_compat",
            side_effect=ValueError("unexpected result validator failure"),
        ):
            exit_code = forge.run_chain(
                self.project,
                "No model call.",
                self.strict_config,
            )

        state = self.assert_failed_supervisor(exit_code)
        self.assertIn("result validator failure", state["stop_reason"])

    def test_termination_contract_exception_terminalizes_supervisor(self) -> None:
        def fake_run(project: Path, _goal: str, _config: Path) -> int:
            forge_dir = project / ".forge"
            forge_dir.mkdir(parents=True, exist_ok=True)
            (forge_dir / "result.json").write_text(
                json.dumps(
                    {
                        "schema_version": forge.SCHEMA_VERSION,
                        "run_id": "invalid-termination",
                        "final_status": "done",
                        "stop_reason_code": "reviewer_continue",
                        "automatic_resume_allowed": True,
                        "final_message": "Invalid structured termination.",
                    }
                ),
                encoding="utf-8",
            )
            return forge.EXIT_NEEDS_CONTINUATION

        with mock.patch.object(
            forge,
            "sandbox_runtime_available",
            return_value=True,
        ), mock.patch.object(
            forge,
            "run_forge",
            side_effect=fake_run,
        ):
            exit_code = forge.run_chain(
                self.project,
                "No model call.",
                self.strict_config,
            )

        state = self.assert_failed_supervisor(exit_code)
        self.assertIn("invalid structured termination", state["stop_reason"])


class InvalidRescueOutcomeTests(unittest.TestCase):
    @staticmethod
    def _standard_outcome() -> forge.RoutedWorkerOutcome:
        return forge.RoutedWorkerOutcome(
            worker=forge.WorkerResult(
                exit_code=7,
                summary="Standard worker did not repair the failing check.",
                raw_output="",
                duration_seconds=1.0,
                model="sonnet",
                effort="medium",
                termination_reason="worker_error",
                valid_worker_outcome=True,
            ),
            worker_calls=1,
        )

    @staticmethod
    def _invalid_rescue(reason: str) -> forge.RoutedWorkerOutcome:
        return forge.RoutedWorkerOutcome(
            worker=forge.WorkerResult(
                exit_code=124 if reason == "timeout" else 1,
                summary=f"Invalid rescue outcome: {reason}",
                raw_output="",
                duration_seconds=2.0,
                model="opus",
                effort="high",
                escalated=True,
                termination_reason=reason,
                valid_worker_outcome=False,
            ),
            worker_calls=1,
            premium_calls=1,
        )

    @staticmethod
    def _config(root: Path) -> Path:
        config = json.loads(
            json.dumps(forge.DEFAULT_CONFIG)
        )
        config.update(
            {
                "max_iterations": 3,
                "runtime_preflight": False,
                "auto_detect_checks": False,
                "checks": [],
                "claude_escalation_enabled": True,
                "claude_escalation_max_per_run": 1,
                "run_scoped_logs": True,
            }
        )
        path = root / "rescue.config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return path

    def _run_case(
        self,
        reason: str,
        *,
        retry_then_block: bool,
    ) -> tuple[int, dict, mock.Mock, list[str]]:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        project = root / "project"
        project.mkdir()
        config_path = self._config(root)
        decisions = [
            forge.Decision(
                status="continue",
                assessment="Attempt the bounded repair.",
                next_prompt="Repair the failing check.",
                acceptance_criteria=["The check passes."],
            )
        ]
        if retry_then_block:
            decisions.append(
                forge.Decision(
                    status="continue",
                    assessment="Retry the exact bounded repair.",
                    next_prompt="Repair the same failing check.",
                    acceptance_criteria=["The check passes."],
                )
            )
            decisions.append(
                forge.Decision(
                    status="blocked",
                    assessment="Stop after proving the retry boundary.",
                    next_prompt=None,
                )
            )
        decision_iter = iter(decisions)
        run_checks = mock.Mock(
            return_value=[
                forge.CheckResult(
                    command="focused tests",
                    exit_code=1,
                    output="one failure",
                    check_id="focused",
                    tier="targeted",
                )
            ]
        )
        routed_profiles: list[str] = []
        routed_outcomes = [
            self._standard_outcome(),
            self._invalid_rescue(reason),
        ]
        if retry_then_block:
            routed_outcomes.append(self._standard_outcome())
        outcomes = iter(routed_outcomes)

        def fake_routed(*_args, **kwargs):
            routed_profiles.append(str(kwargs["profile"]))
            return next(outcomes)

        with mock.patch.object(
            forge,
            "codex_auth_status",
            return_value=(True, "Logged in using ChatGPT"),
        ), mock.patch.object(
            forge,
            "claude_auth_status",
            return_value=(True, '{"loggedIn":true,"subscriptionType":"max"}'),
        ), mock.patch.object(
            forge,
            "ask_orchestrator",
            side_effect=lambda *_args, **_kwargs: next(decision_iter),
        ), mock.patch.object(
            forge,
            "run_claude_routed",
            side_effect=fake_routed,
        ), mock.patch.object(
            forge,
            "run_checks",
            run_checks,
        ):
            exit_code = forge.run_forge(
                project,
                "Exercise invalid rescue handling without model calls.",
                config_path,
            )

        result = json.loads(
            (project / ".forge" / "result.json").read_text(encoding="utf-8")
        )
        return exit_code, result, run_checks, routed_profiles

    def test_invalid_rescue_retries_without_project_or_stuck_accounting(
        self,
    ) -> None:
        exit_code, result, run_checks, profiles = self._run_case(
            "timeout",
            retry_then_block=True,
        )

        self.assertEqual(exit_code, forge.EXIT_BLOCKED)
        self.assertEqual(profiles, ["standard", "rescue", "standard"])
        self.assertEqual(run_checks.call_count, 2)
        self.assertEqual(result["chain_worker_calls"], 3)
        self.assertEqual(result["chain_premium_escalations"], 1)
        self.assertEqual(result["run_premium_claude_escalations_used"], 1)
        self.assertEqual(result["no_progress_count"], 2)
        self.assertEqual(result["failed_iterations"], 2)
        self.assertEqual(result["repeated_failure_count"], 2)
        self.assertEqual(result["escalations"], [])
        self.assertFalse(
            (Path(result["run_directory"]) / "escalations.json").exists()
        )

    def test_invalid_rescue_sandbox_denial_fails_closed(self) -> None:
        exit_code, result, run_checks, profiles = self._run_case(
            "sandbox_denial",
            retry_then_block=False,
        )

        self.assertEqual(exit_code, forge.EXIT_FAILED)
        self.assertEqual(result["final_status"], "failed")
        self.assertIn("sandbox", result["final_message"].lower())
        self.assertEqual(profiles, ["standard", "rescue"])
        self.assertEqual(run_checks.call_count, 1)
        self.assertEqual(result["chain_worker_calls"], 2)
        self.assertEqual(result["chain_premium_escalations"], 1)
        self.assertEqual(result["escalations"], [])

    def test_invalid_rescue_auth_and_subscription_are_terminal(self) -> None:
        expected = {
            "auth_failure": (forge.EXIT_FAILED, "failed"),
            "subscription_limit": (
                forge.EXIT_SUBSCRIPTION_LIMIT,
                "subscription_limit",
            ),
        }
        for reason, (expected_exit, expected_status) in expected.items():
            with self.subTest(reason=reason):
                exit_code, result, run_checks, profiles = self._run_case(
                    reason,
                    retry_then_block=False,
                )
                self.assertEqual(exit_code, expected_exit)
                self.assertEqual(result["final_status"], expected_status)
                self.assertEqual(profiles, ["standard", "rescue"])
                self.assertEqual(run_checks.call_count, 1)
                self.assertEqual(result["chain_worker_calls"], 2)
                self.assertEqual(result["chain_premium_escalations"], 1)
                self.assertEqual(result["escalations"], [])


if __name__ == "__main__":
    unittest.main()
