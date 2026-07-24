from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

import forge
import forge_adaptive as adaptive


class AdaptiveRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "adaptive project"
        self.project.mkdir()
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self.decisions_path = self.root / "decisions.json"
        self.codex_counter = self.root / "codex-counter.txt"
        self.claude_counter = self.root / "claude-counter.txt"
        self._write_fake_codex()
        self._write_fake_claude()

    def tearDown(self):
        self.temp.cleanup()

    def _launcher(self, name: str, script: Path) -> None:
        if os.name == "nt":
            (self.fake_bin / f"{name}.cmd").write_text(
                f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n',
                encoding="utf-8",
            )
        else:
            launcher = self.fake_bin / name
            launcher.write_text(
                f"#!{sys.executable}\nimport runpy; "
                f"runpy.run_path({str(script)!r}, run_name='__main__')\n",
                encoding="utf-8",
            )
            launcher.chmod(0o755)

    def _write_fake_codex(self):
        script = self.fake_bin / "fake_codex.py"
        script.write_text(
            textwrap.dedent(
                """
                import json
                import os
                import sys
                from pathlib import Path

                args = sys.argv[1:]
                if "--help" in args:
                    print("--model --config --json --output-schema --output-last-message")
                    raise SystemExit(0)
                if not args or args[0] != "exec":
                    raise SystemExit(2)
                _ = sys.stdin.read()
                decisions = json.loads(Path(os.environ["FAKE_CODEX_DECISIONS"]).read_text(encoding="utf-8"))
                counter = Path(os.environ["FAKE_CODEX_COUNTER"])
                index = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
                if index >= len(decisions):
                    raise SystemExit(8)
                counter.write_text(str(index + 1), encoding="utf-8")
                output = Path(args[args.index("--output-last-message") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps(decisions[index]), encoding="utf-8")
                print(json.dumps({"type": "turn.completed", "model": "fake-codex", "usage": {"input_tokens": 10, "output_tokens": 5}}))
                raise SystemExit(0)
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        self._launcher("codex", script)

    def _write_fake_claude(self):
        script = self.fake_bin / "fake_claude.py"
        script.write_text(
            textwrap.dedent(
                """
                import json
                import os
                import sys
                from pathlib import Path

                args = sys.argv[1:]
                if "--help" in args:
                    print("--output-format --include-partial-messages --effort --model --fallback-model --no-session-persistence --safe-mode --strict-mcp-config")
                    raise SystemExit(0)
                prompt = sys.stdin.read()
                counter = Path(os.environ["FAKE_CLAUDE_COUNTER"])
                index = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
                index += 1
                counter.write_text(str(index), encoding="utf-8")
                selected_model = (
                    args[args.index("--model") + 1]
                    if "--model" in args
                    else ""
                )
                if selected_model == "fake-cheap":
                    print(json.dumps({
                        "type": "result",
                        "subtype": "error",
                        "is_error": True,
                        "result": "model is unavailable",
                    }), flush=True)
                    raise SystemExit(4)
                Path(f"packet-output-{index}.txt").write_text(
                    f"worker-call={index}\\n" + prompt[:200], encoding="utf-8"
                )
                print(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": f"Implementing packet {index} with {selected_model}"}]}}), flush=True)
                print(json.dumps({"type": "result", "subtype": "success", "is_error": False, "result": f"packet {index} implemented"}), flush=True)
                raise SystemExit(0)
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        self._launcher("claude", script)

    @staticmethod
    def _packet(number: int, tier: str = "targeted") -> dict:
        return {
            "packet_id": f"packet-{number:03d}",
            "title": f"Packet {number}",
            "objective": f"Implement coherent packet {number}.",
            "context": "Fake multi-packet E2E.",
            "dependencies": [] if number == 1 else [f"packet-{number - 1:03d}"],
            "acceptance_criteria": [f"Packet {number} works"],
            "status": "pending",
            "difficulty": (
                "mechanical" if number == 1 else "complex" if number == 3 else "routine"
            ),
            "risk": "low" if number == 1 else "high" if number == 3 else "medium",
            "recommended_worker_profile": (
                "economy" if number == 1 else "complex" if number == 3 else "standard"
            ),
            "recommended_review_profile": "routine_review",
            "check_tier": tier,
            "max_worker_turns": 10 if number == 1 else 20,
            "expected_paths": [],
            "forbidden_scope": [],
            "attempts": 0,
            "last_fingerprint": None,
            "last_failure_signature": None,
            "closes_milestone": tier == "milestone",
            "requires_fresh_release_check": False,
        }

    @staticmethod
    def _continue(packet: int, tier: str) -> dict:
        return {
            "status": "continue",
            "decision_kind": "implement_packet",
            "assessment": f"Continue packet {packet}",
            "active_packet_id": f"packet-{packet:03d}",
            "packet_assessment": "Ready",
            "next_prompt": f"Implement coherent packet {packet}.",
            "acceptance_criteria": [f"Packet {packet} works"],
            "risks": [],
            "recommended_worker_profile": "standard",
            "recommended_worker_effort": "medium",
            "recommended_worker_max_turns": 20,
            "recommended_review_profile": "routine_review",
            "check_tier": tier,
            "check_ids": [],
            "plan_patch": None,
            "routing_reason": "Next dependency-ready packet.",
            "closes_milestone": tier == "milestone",
            "requires_release_check": False,
        }

    @staticmethod
    def _complete(packet: int, tier: str) -> dict:
        payload = AdaptiveRuntimeTests._continue(packet, tier)
        payload.update(
            {
                "status": "done",
                "decision_kind": "complete_packet",
                "assessment": f"Packet {packet} verified",
                "next_prompt": None,
            }
        )
        return payload

    def decisions(self) -> list[dict]:
        architecture = self._continue(1, "targeted")
        architecture["plan_patch"] = {
            "add_packets": [
                self._packet(1, "targeted"),
                self._packet(2, "targeted"),
                self._packet(3, "milestone"),
                self._packet(4, "targeted"),
            ],
            "update_packets": [],
            "active_packet_id": "packet-001",
            "append_milestones": ["Foundation complete", "Feature complete"],
            "append_release_gates": ["Release checks pass"],
            "append_architectural_decisions": ["Use local deterministic fixtures"],
            "append_safe_assumptions": ["The fake project remains offline."],
            "append_risks": ["Preserve immutable run evidence"],
            "explanation": "Four coherent dependency-ordered packets.",
        }
        final = self._complete(4, "release")
        final.update(
            {
                "decision_kind": "complete_project",
                "assessment": "All packets and fresh release evidence are complete.",
                "recommended_review_profile": "final_review",
                "check_tier": "release",
                "requires_release_check": True,
            }
        )
        return [
            architecture,
            self._complete(1, "targeted"),
            self._complete(2, "targeted"),
            self._complete(3, "milestone"),
            self._complete(4, "targeted"),
            final,
        ]

    def config(self) -> dict:
        config = forge.DEFAULT_CONFIG.copy()
        config.update(
            {
                "adaptive_orchestration": True,
                "adaptive_auto_supervisor": True,
                "runtime_preflight": True,
                "max_iterations": 2,
                "auto_detect_checks": False,
                "sandbox_checks": "off",
                "claude_escalation_enabled": False,
                "heartbeat_interval_seconds": 1,
                "check_definitions": [
                    {
                        "check_id": "smoke",
                        "command": "git diff --check",
                        "tier": "smoke",
                        "timeout_seconds": 30,
                    },
                    {
                        "check_id": "targeted",
                        "command": f'"{sys.executable}" -c "print(\'Ran 1 tests\')"',
                        "tier": "targeted",
                        "timeout_seconds": 30,
                        "test_count_pattern": "Ran (?P<count>\\d+) tests?",
                        "required_before_done": True,
                    },
                    {
                        "check_id": "milestone",
                        "command": f'"{sys.executable}" -c "print(\'Ran 2 tests\')"',
                        "tier": "milestone",
                        "timeout_seconds": 30,
                        "test_count_pattern": "Ran (?P<count>\\d+) tests?",
                        "required_before_done": True,
                    },
                    {
                        "check_id": "release",
                        "command": f'"{sys.executable}" -c "print(\'Ran 3 tests\')"',
                        "tier": "release",
                        "timeout_seconds": 30,
                        "test_count_pattern": "Ran (?P<count>\\d+) tests?",
                        "required_before_done": True,
                    },
                ],
                "checks": [],
                "chain_budgets": {
                    "max_child_runs": 5,
                    "max_codex_calls": 15,
                    "max_worker_calls": 8,
                    "max_elapsed_seconds": 600,
                    "max_full_check_suites": 6,
                    "max_premium_escalations": 1,
                    "max_no_progress_events": 5,
                },
            }
        )
        config["adaptive_profiles"] = json.loads(
            json.dumps(config["adaptive_profiles"])
        )
        config["adaptive_profiles"]["claude"]["economy"]["candidates"] = [
            {
                "model": "fake-cheap",
                "effort": "low",
                "requires_subscription_confirmation": True,
            },
            {"model": "sonnet", "effort": "low"},
        ]
        config["confirmed_subscription_models"] = ["fake-cheap"]
        return config

    def test_complete_fake_cli_multi_packet_chain_reaches_done(self):
        self.decisions_path.write_text(
            json.dumps(self.decisions()), encoding="utf-8"
        )
        config_path = self.root / "adaptive.config.json"
        config_path.write_text(json.dumps(self.config()), encoding="utf-8")
        env = {
            "PATH": str(self.fake_bin) + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_CODEX_DECISIONS": str(self.decisions_path),
            "FAKE_CODEX_COUNTER": str(self.codex_counter),
            "FAKE_CLAUDE_COUNTER": str(self.claude_counter),
            "FAKE_CLAUDE_REJECT_MODEL": "fake-cheap",
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
            forge, "codex_auth_status", return_value=(True, "Logged in using ChatGPT")
        ), mock.patch.object(
            forge,
            "claude_auth_status",
            return_value=(True, '{"loggedIn":true,"subscriptionType":"max"}'),
        ), mock.patch.object(
            forge, "WORKER_BOUNDARIES", "TEST BOUNDARIES"
        ), mock.patch.object(
            forge, "sandbox_runtime_available", return_value=True
        ):
            exit_code = forge.run_chain(
                self.project, "Build a four-packet fake application", config_path
            )
        self.assertEqual(exit_code, forge.EXIT_DONE)
        result = json.loads(
            (self.project / ".forge" / "result.json").read_text(encoding="utf-8")
        )
        plan = json.loads(
            (self.project / ".forge" / "project-plan.json").read_text(
                encoding="utf-8"
            )
        )
        supervisor = json.loads(
            (self.project / ".forge" / "chain-supervisor.json").read_text(
                encoding="utf-8"
            )
        )
        status = json.loads(
            (self.project / ".forge" / "status.json").read_text(encoding="utf-8")
        )
        chain_telemetry = json.loads(
            (self.project / ".forge" / "chain-telemetry.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(result["final_status"], "done")
        self.assertEqual(plan["status"], "done")
        self.assertEqual(len(plan["work_packets"]), 4)
        self.assertEqual(len(plan["completed_packet_ids"]), 4)
        self.assertEqual(result["last_check_tier"], "release")
        self.assertEqual(result["last_release_check_run_id"], result["run_id"])
        self.assertEqual(result["chain_worker_calls"], 5)
        self.assertEqual(result["chain_model_fallbacks"], 1)
        self.assertTrue(
            any(
                (check.get("tests_executed") or 0) > 0
                for check in result["checks"]
            )
        )
        self.assertEqual(result["chain_child_runs"], 3)
        self.assertEqual(supervisor["status"], "done")
        self.assertEqual(status["packet_completed"], 4)
        self.assertFalse(status["model_polling"])
        self.assertGreater(status["requested_turn_budget"], 0)
        self.assertFalse(status["cli_turn_limit_enforced"])
        self.assertTrue((self.project / "ASSUMPTIONS.md").is_file())
        self.assertEqual(int(self.codex_counter.read_text(encoding="utf-8")), 6)
        self.assertEqual(int(self.claude_counter.read_text(encoding="utf-8")), 5)
        profiles = {
            profile
            for run in chain_telemetry["runs"]
            for profile in run["claude_calls_by_profile"]
        }
        self.assertTrue({"economy", "complex"}.issubset(profiles))
        self.assertTrue(
            all(
                "cli_turn_limit_enforced" in record
                for run in chain_telemetry["runs"]
                for record in run["turn_budget_records"]
            )
        )
        runs = sorted((self.project / ".forge" / "runs").iterdir())
        self.assertEqual(len(runs), 4)
        for run in runs:
            self.assertTrue((run / "project-plan.result.json").is_file())
            telemetry = json.loads(
                (run / "telemetry.json").read_text(encoding="utf-8")
            )
            self.assertFalse(telemetry["raw_prompts_stored"])
            self.assertFalse(telemetry["private_reasoning_stored"])

    def test_self_installation_is_rejected(self):
        with self.assertRaises(SystemExit):
            forge.validate_project_path(Path(forge.__file__).resolve().parent)

    def test_copied_forge_metadata_is_rejected(self):
        first = self.root / "first"
        second = self.root / "second"
        first.mkdir()
        second.mkdir()
        adaptive.stable_project_identity(first)
        shutil.copytree(first / ".forge", second / ".forge")
        with self.assertRaises(RuntimeError):
            adaptive.stable_project_identity(second)

    def test_ambiguous_latest_without_pointer_is_rejected(self):
        runs = self.project / ".forge" / "runs"
        for name in ("run-a", "run-b"):
            directory = runs / name
            directory.mkdir(parents=True)
            (directory / "result.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            forge.resolve_resume_run_directory(self.project, "latest")

    def test_schema_two_result_remains_readable(self):
        path = self.root / "schema2.json"
        path.write_text(
            json.dumps({"schema_version": 2, "run_id": "old", "final_status": "done"}),
            encoding="utf-8",
        )
        payload = forge.read_result_compat(path)
        self.assertEqual(payload["schema_version"], 2)
        self.assertIsNone(payload["continuation"])

    def test_adaptive_resume_rejects_wrong_project_id(self):
        identity = adaptive.stable_project_identity(self.project)
        config = forge.DEFAULT_CONFIG.copy()
        config["adaptive_orchestration"] = True
        contract = forge.ensure_check_contract(self.project, config)
        plan = adaptive.load_or_create_plan(self.project, "Safe goal")
        plan.check_contract_hash = contract.contract_hash
        adaptive.save_plan(self.project, plan)
        run = self.project / ".forge" / "runs" / "source-run"
        run.mkdir(parents=True)
        (run / "run.json").write_text(
            json.dumps({"goal": "Safe goal", "config": config}),
            encoding="utf-8",
        )
        continuation = forge.ContinuationPayload(
            source_run_id="source-run",
            continuation_chain_id="chain-1",
            next_prompt="Continue the exact active packet.",
            acceptance_criteria=["Packet works"],
            repository_fingerprint="fingerprint",
            repository_manifest={},
            project_id=f"wrong-{identity['project_id']}",
            plan_id=plan.plan_id,
            plan_hash=adaptive.plan_hash(plan),
            chain_child_runs=1,
            chain_codex_calls=1,
            chain_no_progress_events=0,
            check_contract_hash=contract.contract_hash,
        )
        (run / "result.json").write_text(
            json.dumps(
                {
                    "schema_version": forge.SCHEMA_VERSION,
                    "run_id": "source-run",
                    "final_status": "needs_continuation",
                    "stop_reason_code": "reviewer_continue",
                    "automatic_resume_allowed": True,
                    "goal": "Safe goal",
                    "continuation": continuation.model_dump(mode="json"),
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "identity"):
            forge.load_resume_context(self.project, "source-run")

    def test_heartbeat_is_local_and_updates_without_models(self):
        tracker = forge.StatusTracker(self.project, "Goal", "run-1")
        before = tracker.snapshot()["heartbeat_sequence"]
        stop, thread = forge.start_local_heartbeat(tracker, 1)
        thread.join(timeout=1.3)
        stop.set()
        thread.join(timeout=2)
        after = json.loads(
            (self.project / ".forge" / "status.json").read_text(encoding="utf-8")
        )
        self.assertGreater(after["heartbeat_sequence"], before)
        self.assertFalse(after["model_polling"])


class SupervisorTerminalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.project = Path(self.temp.name) / "project"
        self.project.mkdir()
        self.sandbox = mock.patch.object(
            forge, "sandbox_runtime_available", return_value=True
        )
        self.sandbox.start()

    def tearDown(self):
        self.sandbox.stop()
        self.temp.cleanup()

    def _terminal(self, code: int) -> tuple[int, mock.Mock]:
        resume = mock.Mock()
        with mock.patch.object(forge, "run_forge", return_value=code), mock.patch.object(
            forge, "resume_forge", resume
        ):
            result = forge.run_chain(
                self.project,
                "Goal",
                Path(forge.__file__).with_name("forge.config.json"),
            )
        return result, resume

    def _write_needs_result(
        self,
        *,
        message: str = "Continue safely",
        continuation: object = None,
        schema_version: int = 3,
        stop_reason_code: str | None = None,
        automatic_resume_allowed: bool | None = None,
    ) -> None:
        forge_dir = self.project / ".forge"
        forge_dir.mkdir(parents=True, exist_ok=True)
        if continuation is None:
            continuation = {"next_prompt": "Exact inherited packet."}
        payload = {
            "schema_version": schema_version,
            "run_id": "source-run",
            "final_status": "needs_continuation",
            "final_message": message,
            "continuation": continuation,
            "chain_child_runs": 1,
        }
        if stop_reason_code is not None:
            payload["stop_reason_code"] = stop_reason_code
        if automatic_resume_allowed is not None:
            payload["automatic_resume_allowed"] = automatic_resume_allowed
        (forge_dir / "result.json").write_text(
            json.dumps(payload),
            encoding="utf-8",
        )

    def test_blocked_stops_supervisor(self):
        result, resume = self._terminal(forge.EXIT_BLOCKED)
        self.assertEqual(result, forge.EXIT_BLOCKED)
        resume.assert_not_called()

    def test_failed_stops_supervisor(self):
        result, resume = self._terminal(forge.EXIT_FAILED)
        self.assertEqual(result, forge.EXIT_FAILED)
        resume.assert_not_called()

    def test_subscription_limit_stops_supervisor(self):
        result, resume = self._terminal(forge.EXIT_SUBSCRIPTION_LIMIT)
        self.assertEqual(result, forge.EXIT_SUBSCRIPTION_LIMIT)
        resume.assert_not_called()

    def test_unattended_chain_without_sandbox_stops_before_worker(self):
        run = mock.Mock(return_value=forge.EXIT_DONE)
        with mock.patch.object(
            forge, "sandbox_runtime_available", return_value=False
        ), mock.patch.object(forge, "run_forge", run):
            result = forge.run_chain(
                self.project,
                "Goal",
                Path(forge.__file__).with_name("forge.config.json"),
            )
        self.assertEqual(result, forge.EXIT_FAILED)
        run.assert_not_called()
        state = json.loads(
            (self.project / ".forge" / "chain-supervisor.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(state["stop_reason_code"], "technical_failure")

    def test_budget_exhaustion_stops_without_another_child(self):
        self._write_needs_result(
            message="Continuation chain budget exhausted: child runs=2, limit=2."
        )
        resume = mock.Mock()
        with mock.patch.object(
            forge, "run_forge", return_value=forge.EXIT_NEEDS_CONTINUATION
        ), mock.patch.object(forge, "resume_forge", resume):
            result = forge.run_chain(
                self.project,
                "Goal",
                Path(forge.__file__).with_name("forge.config.json"),
            )
        self.assertEqual(result, forge.EXIT_NEEDS_CONTINUATION)
        resume.assert_not_called()

    def test_structured_budget_exhaustion_stops_without_text_dependency(self):
        self._write_needs_result(
            schema_version=forge.SCHEMA_VERSION,
            message="Any localized human message.",
            stop_reason_code="chain_budget_exhausted",
            automatic_resume_allowed=False,
        )
        resume = mock.Mock()
        with mock.patch.object(
            forge, "run_forge", return_value=forge.EXIT_NEEDS_CONTINUATION
        ), mock.patch.object(forge, "resume_forge", resume):
            result = forge.run_chain(
                self.project,
                "Goal",
                Path(forge.__file__).with_name("forge.config.json"),
            )
        self.assertEqual(result, forge.EXIT_NEEDS_CONTINUATION)
        resume.assert_not_called()

    def test_current_result_ignores_budget_words_in_human_message(self):
        self._write_needs_result(
            schema_version=forge.SCHEMA_VERSION,
            message="Budget exhausted is merely human prose here.",
            stop_reason_code="next_packet_ready",
            automatic_resume_allowed=True,
        )
        with mock.patch.object(
            forge, "run_forge", return_value=forge.EXIT_NEEDS_CONTINUATION
        ), mock.patch.object(
            forge, "resume_forge", return_value=forge.EXIT_DONE
        ) as resume:
            result = forge.run_chain(
                self.project,
                "Goal",
                Path(forge.__file__).with_name("forge.config.json"),
            )
        self.assertEqual(result, forge.EXIT_DONE)
        resume.assert_called_once_with(self.project.resolve(), "source-run")

    def test_next_packet_and_reviewer_continue_are_resumable(self):
        for reason in ("next_packet_ready", "reviewer_continue"):
            with self.subTest(reason=reason):
                if (self.project / ".forge").exists():
                    shutil.rmtree(self.project / ".forge")
                self._write_needs_result(
                    schema_version=forge.SCHEMA_VERSION,
                    stop_reason_code=reason,
                    automatic_resume_allowed=True,
                )
                with mock.patch.object(
                    forge, "run_forge", return_value=forge.EXIT_NEEDS_CONTINUATION
                ), mock.patch.object(
                    forge, "resume_forge", return_value=forge.EXIT_DONE
                ) as resume:
                    result = forge.run_chain(
                        self.project,
                        "Goal",
                        Path(forge.__file__).with_name("forge.config.json"),
                    )
                self.assertEqual(result, forge.EXIT_DONE)
                resume.assert_called_once()

    def test_automatic_resume_false_stops_even_with_valid_prompt(self):
        self._write_needs_result(
            schema_version=forge.SCHEMA_VERSION,
            stop_reason_code="packet_attempts_exhausted",
            automatic_resume_allowed=False,
        )
        resume = mock.Mock()
        with mock.patch.object(
            forge, "run_forge", return_value=forge.EXIT_NEEDS_CONTINUATION
        ), mock.patch.object(forge, "resume_forge", resume):
            result = forge.run_chain(
                self.project,
                "Goal",
                Path(forge.__file__).with_name("forge.config.json"),
            )
        self.assertEqual(result, forge.EXIT_NEEDS_CONTINUATION)
        resume.assert_not_called()

    def test_invalid_status_reason_combination_is_rejected(self):
        with self.assertRaises(ValueError):
            forge.ResultTermination(
                final_status="done",
                stop_reason_code="reviewer_continue",
                automatic_resume_allowed=True,
            )

    def test_ambiguous_legacy_result_stops_safely(self):
        self._write_needs_result(
            schema_version=3,
            message="Unclear legacy continuation.",
            continuation={"next_prompt": ""},
        )
        resume = mock.Mock()
        with mock.patch.object(
            forge, "run_forge", return_value=forge.EXIT_NEEDS_CONTINUATION
        ), mock.patch.object(forge, "resume_forge", resume):
            result = forge.run_chain(
                self.project,
                "Goal",
                Path(forge.__file__).with_name("forge.config.json"),
            )
        self.assertEqual(result, forge.EXIT_FAILED)
        resume.assert_not_called()

    def test_corrupted_continuation_is_not_executed(self):
        self._write_needs_result(continuation={"next_prompt": ""})
        resume = mock.Mock()
        with mock.patch.object(
            forge, "run_forge", return_value=forge.EXIT_NEEDS_CONTINUATION
        ), mock.patch.object(forge, "resume_forge", resume):
            result = forge.run_chain(
                self.project,
                "Goal",
                Path(forge.__file__).with_name("forge.config.json"),
            )
        self.assertEqual(result, forge.EXIT_FAILED)
        resume.assert_not_called()

    def test_supervisor_uses_exact_source_run_id(self):
        self._write_needs_result()
        with mock.patch.object(
            forge, "run_forge", return_value=forge.EXIT_NEEDS_CONTINUATION
        ), mock.patch.object(
            forge, "resume_forge", return_value=forge.EXIT_DONE
        ) as resume:
            result = forge.run_chain(
                self.project,
                "Generic goal that must not be restarted",
                Path(forge.__file__).with_name("forge.config.json"),
            )
        self.assertEqual(result, forge.EXIT_DONE)
        resume.assert_called_once_with(self.project.resolve(), "source-run")


if __name__ == "__main__":
    unittest.main()
