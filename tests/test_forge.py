from __future__ import annotations

import io
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock


STAGING = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STAGING))
import forge  # noqa: E402


class StreamParserTests(unittest.TestCase):
    def make_processor(self):
        raw = io.StringIO()
        live = io.StringIO()
        processor = forge.ClaudeStreamProcessor(raw, live, echo=False)
        return processor, raw, live

    def test_parses_stream_json_text_event(self):
        processor, _, live = self.make_processor()
        events = processor.process_line(
            json.dumps(
                {
                    "type": "assistant",
                    "message": {"content": [{"type": "text", "text": "Hotovo."}]},
                }
            )
        )
        self.assertEqual(events[0]["label"], "Text")
        self.assertIn("Hotovo.", live.getvalue())

    def test_parses_tool_use_event(self):
        processor, _, _ = self.make_processor()
        events = processor.process_line(
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "tool-1",
                                "name": "Edit",
                                "input": {"file_path": "src/App.tsx", "new_string": "safe"},
                            }
                        ]
                    },
                }
            )
        )
        self.assertEqual(events[0]["label"], "Edit")
        self.assertEqual(events[0]["current_file"], "src/App.tsx")

    def test_parses_tool_result_event(self):
        processor, _, live = self.make_processor()
        processor.process_line(
            json.dumps(
                {
                    "type": "tool_use",
                    "id": "tool-2",
                    "name": "Bash",
                    "input": {"command": "npm test"},
                }
            )
        )
        events = processor.process_line(
            json.dumps(
                {
                    "type": "tool_result",
                    "tool_use_id": "tool-2",
                    "content": {"stdout": "ok", "exit_code": 0},
                }
            )
        )
        self.assertEqual(events[0]["label"], "Result")
        self.assertIn("exit 0", live.getvalue())

    def test_unknown_event_is_kept_in_raw_jsonl(self):
        processor, raw, _ = self.make_processor()
        processor.process_line(json.dumps({"type": "future_event", "value": 7}))
        saved = json.loads(raw.getvalue())
        self.assertEqual(saved["type"], "future_event")

    def test_invalid_json_line_does_not_crash(self):
        processor, raw, live = self.make_processor()
        events = processor.process_line("not-json")
        self.assertEqual(events[0]["label"], "InvalidJSON")
        self.assertIn('"type": "invalid_json"', raw.getvalue())
        self.assertIn("not-json", live.getvalue())

    def test_redacts_secrets_and_private_reasoning(self):
        fake_anthropic_token = "sk-" + "ant-" + "abcdefghijklmnopqrstuvwxyz"
        text = (
            "Authorization: Bearer abcdefghijklmnop\n"
            f"ANTHROPIC_API_KEY={fake_anthropic_token}\n"
            "postgres://user:password@localhost/db"
        )
        clean = forge.redact_text(text)
        self.assertNotIn("abcdefghijklmnop", clean)
        self.assertNotIn(fake_anthropic_token, clean)
        self.assertNotIn("user:password", clean)
        event = forge.redact_data(
            {"type": "thinking", "thinking": "private chain", "signature": "secret"}
        )
        serialized = json.dumps(event)
        self.assertNotIn("private chain", serialized)
        self.assertNotIn('"secret"', serialized)


class StatusAndPromptTests(unittest.TestCase):
    def test_status_json_updates_atomically(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            tracker = forge.StatusTracker(project, "Test goal", "run-1")
            tracker.set_phase(
                "claude_implementation",
                iteration=2,
                current_agent="Claude Code",
                message="Working",
            )
            tracker.update_event(
                current_tool="Edit",
                current_file="src/App.tsx",
                message="Editing",
            )
            status = json.loads((project / ".forge" / "status.json").read_text(encoding="utf-8"))
            self.assertEqual(status["iteration"], 2)
            self.assertEqual(status["phase"], "claude_implementation")
            self.assertEqual(status["current_file"], "src/App.tsx")
            self.assertFalse(list((project / ".forge").glob("status.json.*.tmp")))

    def test_prompt_log_contains_required_sections(self):
        decision = forge.Decision(
            status="continue",
            assessment="Implement",
            next_prompt="Add the screen.",
            acceptance_criteria=["Tests pass"],
            risks=[],
        )
        prompt = forge.build_worker_prompt("Product goal", decision)
        with tempfile.TemporaryDirectory() as temp:
            path = forge.write_prompt_log(Path(temp), 3, prompt)
            content = path.read_text(encoding="utf-8")
        self.assertIn("OVERALL PRODUCT GOAL", content)
        self.assertIn("CURRENT ORCHESTRATOR TASK", content)
        self.assertIn("CURRENT ACCEPTANCE CRITERIA", content)
        self.assertIn("WORKER BOUNDARIES", content)


class OrchestratorTests(unittest.TestCase):
    def test_codex_output_schema_requires_every_declared_property(self):
        objects_with_properties = []

        def visit(value):
            if isinstance(value, dict):
                properties = value.get("properties")
                if isinstance(properties, dict):
                    objects_with_properties.append(value)
                for item in value.values():
                    visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)

        visit(forge.DECISION_SCHEMA)
        self.assertTrue(objects_with_properties)
        for schema_object in objects_with_properties:
            self.assertEqual(
                schema_object["required"],
                list(schema_object["properties"]),
            )

    def test_large_codex_prompt_is_passed_via_stdin(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            output_path = project / ".forge" / "decision.json"
            captured = {}

            def fake_run(cmd, **kwargs):
                captured["cmd"] = cmd
                captured["input"] = kwargs.get("input")
                output_arg = Path(cmd[cmd.index("--output-last-message") + 1])
                output_arg.parent.mkdir(parents=True, exist_ok=True)
                output_arg.write_text(
                    json.dumps(
                        {
                            "status": "continue",
                            "assessment": "Continue",
                            "next_prompt": "Implement",
                            "acceptance_criteria": [],
                            "risks": [],
                        }
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with mock.patch.object(forge.shutil, "which", return_value="codex"), mock.patch.object(
                forge.subprocess, "run", side_effect=fake_run
            ):
                decision = forge.ask_orchestrator(
                    project,
                    "X" * 50000,
                    forge.DEFAULT_CONFIG.copy(),
                    output_path,
                )
        self.assertEqual(decision.status, "continue")
        self.assertGreater(len(captured["input"]), 50000)
        self.assertNotIn(captured["input"], captured["cmd"])
        self.assertIn("--model", captured["cmd"])
        self.assertIn("gpt-5.6-terra", captured["cmd"])
        self.assertIn('model_reasoning_effort="medium"', captured["cmd"])

    def test_phase_specific_codex_profiles(self):
        config = forge.DEFAULT_CONFIG.copy()
        self.assertEqual(
            forge.select_codex_profile(config, "architecture"),
            ("gpt-5.6-sol", "xhigh"),
        )
        self.assertEqual(
            forge.select_codex_profile(config, "review"),
            ("gpt-5.6-terra", "medium"),
        )
        self.assertEqual(
            forge.select_codex_profile(config, "final"),
            ("gpt-5.6-sol", "xhigh"),
        )
        self.assertEqual(
            forge.select_codex_profile(config, "review", important=True),
            ("gpt-5.6-sol", "high"),
        )


class FakeClaudeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project with spaces"
        self.project.mkdir()
        self.logs = self.project / ".forge" / "logs"
        self.logs.mkdir(parents=True)
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self.args_file = self.root / "args.json"
        self._write_fake_claude()
        self.decision = forge.Decision(
            status="continue",
            assessment="Test worker",
            next_prompt="Run the simulated implementation.",
            acceptance_criteria=["Simulation passes"],
            risks=[],
        )

    def tearDown(self):
        self.temp.cleanup()

    def _write_fake_claude(self):
        script = self.fake_bin / "fake_claude.py"
        script.write_text(
            textwrap.dedent(
                """
                import json
                import os
                import sys
                import time

                mode = os.environ.get("FAKE_CLAUDE_MODE", "success")
                args_file = os.environ.get("FAKE_ARGS_FILE")
                if args_file:
                    with open(args_file, "w", encoding="utf-8") as handle:
                        json.dump(sys.argv[1:], handle)
                _ = sys.stdin.read()
                if mode == "timeout":
                    time.sleep(3)
                    raise SystemExit(0)
                if mode == "max_turns_progress":
                    with open("progress.txt", "w", encoding="utf-8") as handle:
                        handle.write("relevant implementation progress\\n")
                print(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "Working"}]}}), flush=True)
                print(json.dumps({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "b1", "name": "Bash", "input": {"command": "python -m unittest"}}]}}), flush=True)
                print(json.dumps({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "b1", "content": {"stdout": "OK", "exit_code": 0}}]}}), flush=True)
                if mode == "missing_final":
                    raise SystemExit(0)
                if mode == "subscription":
                    print(json.dumps({"type": "result", "subtype": "error", "is_error": True, "result": "usage limit reached"}), flush=True)
                    raise SystemExit(1)
                selected_model = sys.argv[sys.argv.index("--model") + 1] if "--model" in sys.argv else ""
                if mode == "escalate" and selected_model != "opus":
                    print(json.dumps({"type": "result", "subtype": "error", "is_error": True, "result": "standard worker stuck"}), flush=True)
                    raise SystemExit(7)
                if mode == "nonzero":
                    print(json.dumps({"type": "result", "subtype": "error", "is_error": True, "result": "worker failed"}), flush=True)
                    raise SystemExit(7)
                if mode == "max_turns_progress":
                    print(json.dumps({"type": "result", "subtype": "error_max_turns", "is_error": True, "result": "error_max_turns"}), flush=True)
                    raise SystemExit(1)
                print(json.dumps({"type": "result", "subtype": "success", "is_error": False, "result": "simulated done"}), flush=True)
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        if os.name == "nt":
            launcher = self.fake_bin / "claude.cmd"
            launcher.write_text(
                f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n',
                encoding="utf-8",
            )
        else:
            launcher = self.fake_bin / "claude"
            launcher.write_text(
                f"#!{sys.executable}\nimport runpy; runpy.run_path({str(script)!r}, run_name='__main__')\n",
                encoding="utf-8",
            )
            launcher.chmod(0o755)

    def config(self, timeout=10):
        config = forge.DEFAULT_CONFIG.copy()
        config.update(
            {
                "claude_timeout_seconds": timeout,
                "claude_max_turns": 3,
                "claude_model": "sonnet",
                "permission_mode": "auto",
            }
        )
        return config

    def run_worker(self, mode="success", timeout=10):
        env = {
            "PATH": str(self.fake_bin) + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_CLAUDE_MODE": mode,
            "FAKE_ARGS_FILE": str(self.args_file),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            # Keep the Windows .cmd shim single-line; prompt structure itself is
            # covered separately by StatusAndPromptTests.
            with mock.patch.object(forge, "WORKER_BOUNDARIES", "TEST BOUNDARIES"):
                return forge.run_claude(
                    self.project,
                    "Simulated product",
                    self.decision,
                    self.config(timeout),
                    iteration=1,
                    logs=self.logs,
                )

    def test_preserves_final_worker_result_and_stream_flags(self):
        result = self.run_worker()
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.summary, "simulated done")
        self.assertTrue((self.logs / "01-claude-prompt.txt").exists())
        self.assertTrue((self.logs / "01-claude-stream.jsonl").exists())
        self.assertTrue((self.logs / "01-claude-live.log").exists())
        args = json.loads(self.args_file.read_text(encoding="utf-8"))
        self.assertIn("--safe-mode", args)
        self.assertIn("--strict-mcp-config", args)
        self.assertIn("--allowedTools", args)
        allowed_tools_index = args.index("--allowedTools")
        self.assertEqual(args[allowed_tools_index + 1], "Bash,Read,Edit,Write,Glob,Grep")
        self.assertIn("stream-json", args)
        self.assertIn("--verbose", args)
        self.assertIn("--include-partial-messages", args)
        self.assertIn("--no-session-persistence", args)
        self.assertIn("--effort", args)
        self.assertIn("medium", args)

    def test_timeout_returns_worker_result(self):
        result = self.run_worker(mode="timeout", timeout=1)
        self.assertEqual(result.exit_code, 124)
        self.assertIn("časový limit", result.summary)

    def test_nonzero_exit_is_preserved(self):
        result = self.run_worker(mode="nonzero")
        self.assertEqual(result.exit_code, 7)
        self.assertIn("worker failed", result.summary)

    def test_subscription_limit_stops_without_api_fallback(self):
        with self.assertRaises(forge.SubscriptionLimitError) as caught:
            self.run_worker(mode="subscription")
        self.assertIsNotNone(caught.exception.worker_result)
        self.assertNotEqual(caught.exception.worker_result.exit_code, 0)

    def test_missing_final_event_is_not_success(self):
        result = self.run_worker(mode="missing_final")
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("bez platného finálneho result eventu", result.summary)

    def test_simulated_streaming_end_to_end_cycle(self):
        config = self.config(timeout=10)
        config.update({
            "max_iterations": 2,
            "auto_detect_checks": False,
            "checks": [],
            "runtime_preflight": False,
            "claude_escalation_enabled": False,
            "run_scoped_logs": True,
        })
        config_path = self.root / "forge.test.config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        decisions = iter(
            [
                forge.Decision(
                    status="continue",
                    assessment="Implement simulated change",
                    next_prompt="Run the simulated worker.",
                    acceptance_criteria=["Checks pass"],
                    risks=[],
                ),
                forge.Decision(
                    status="done",
                    assessment="Simulation complete",
                    next_prompt=None,
                    acceptance_criteria=["Checks pass"],
                    risks=[],
                ),
            ]
        )
        env = {
            "PATH": str(self.fake_bin) + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_CLAUDE_MODE": "success",
            "FAKE_ARGS_FILE": str(self.args_file),
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
            forge, "WORKER_BOUNDARIES", "TEST BOUNDARIES"
        ), mock.patch.object(
            forge, "codex_auth_status", return_value=(True, "Logged in using ChatGPT")
        ), mock.patch.object(
            forge,
            "claude_auth_status",
            return_value=(True, '{"loggedIn":true,"subscriptionType":"max"}'),
        ), mock.patch.object(
            forge, "ask_orchestrator", side_effect=lambda *args, **kwargs: next(decisions)
        ):
            exit_code = forge.run_forge(
                self.project,
                "Simulated end-to-end goal",
                config_path,
            )
        self.assertEqual(exit_code, 0)
        status = json.loads(
            (self.project / ".forge" / "status.json").read_text(encoding="utf-8")
        )
        result = json.loads(
            (self.project / ".forge" / "result.json").read_text(encoding="utf-8")
        )
        self.assertEqual(status["phase"], "done")
        self.assertEqual(result["final_status"], "done")
        run_logs = Path(result["logs_path"])
        self.assertTrue((run_logs / "01-claude-stream.jsonl").exists())
        self.assertTrue((run_logs / "01-worker.json").exists())
        self.assertTrue((run_logs / "01-checks.json").exists())
        self.assertIn("runs", run_logs.parts)

    def test_end_to_end_uses_one_premium_escalation_when_standard_worker_fails(self):
        config = self.config(timeout=10)
        config.update({
            "max_iterations": 1,
            "auto_detect_checks": False,
            "checks": [],
            "runtime_preflight": False,
            "claude_escalation_enabled": True,
            "claude_escalation_max_per_run": 1,
            "run_scoped_logs": True,
        })
        config_path = self.root / "forge.escalation.config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        decisions = iter([
            forge.Decision(
                status="continue",
                assessment="Implement",
                next_prompt="Run the worker.",
                acceptance_criteria=["Checks pass"],
                risks=[],
            ),
            forge.Decision(
                status="done",
                assessment="Escalation fixed the issue",
                next_prompt=None,
                acceptance_criteria=["Checks pass"],
                risks=[],
            ),
        ])
        env = {
            "PATH": str(self.fake_bin) + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_CLAUDE_MODE": "escalate",
            "FAKE_ARGS_FILE": str(self.args_file),
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
            forge, "WORKER_BOUNDARIES", "TEST BOUNDARIES"
        ), mock.patch.object(
            forge, "codex_auth_status", return_value=(True, "Logged in using ChatGPT")
        ), mock.patch.object(
            forge, "claude_auth_status", return_value=(True, '{"loggedIn":true,"subscriptionType":"max"}')
        ), mock.patch.object(
            forge, "ask_orchestrator", side_effect=lambda *args, **kwargs: next(decisions)
        ):
            exit_code = forge.run_forge(self.project, "Escalation goal", config_path)
        result = json.loads((self.project / ".forge" / "result.json").read_text(encoding="utf-8"))
        run_logs = Path(result["logs_path"])
        args = json.loads(self.args_file.read_text(encoding="utf-8"))
        self.assertEqual(exit_code, 0)
        self.assertEqual(result["premium_claude_escalations_used"], 1)
        self.assertTrue((run_logs / "01E1-worker.json").exists())
        self.assertIn("opus", args)
        self.assertIn("high", args)

    def continuation_config(self):
        config = self.config(timeout=10)
        config.update({
            "max_iterations": 1,
            "auto_detect_checks": False,
            "checks": [],
            "runtime_preflight": False,
            "claude_escalation_enabled": False,
            "run_scoped_logs": True,
            "final_review_after_last_worker": True,
        })
        return config

    def _run_operation(self, operation, decisions, *, mode="success"):
        calls = []
        decision_iter = iter(decisions)

        def fake_ask(_project, prompt, _config, _output, **kwargs):
            calls.append({"prompt": prompt, **kwargs})
            item = next(decision_iter)
            if isinstance(item, Exception):
                raise item
            return item

        env = {
            "PATH": str(self.fake_bin) + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_CLAUDE_MODE": mode,
            "FAKE_ARGS_FILE": str(self.args_file),
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
            forge, "WORKER_BOUNDARIES", "TEST BOUNDARIES"
        ), mock.patch.object(
            forge, "codex_auth_status", return_value=(True, "Logged in using ChatGPT")
        ), mock.patch.object(
            forge,
            "claude_auth_status",
            return_value=(True, '{"loggedIn":true,"subscriptionType":"max"}'),
        ), mock.patch.object(
            forge, "ask_orchestrator", side_effect=fake_ask
        ):
            exit_code = operation()
        return exit_code, calls

    def _create_needs_continuation(self, *, next_prompt="Finish exact feature."):
        config = self.continuation_config()
        config_path = self.root / "forge.continuation.config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        decisions = [
            forge.Decision(
                status="continue",
                assessment="Implement the feature",
                next_prompt="Implement initial feature.",
                acceptance_criteria=["Feature works", "Checks pass"],
                risks=["Preserve existing behavior"],
            ),
            forge.Decision(
                status="continue",
                assessment="One precise follow-up remains",
                next_prompt=next_prompt,
                acceptance_criteria=["Feature works", "Checks pass"],
                risks=["Preserve existing behavior"],
            ),
        ]
        exit_code, calls = self._run_operation(
            lambda: forge.run_forge(
                self.project,
                "Continuation product goal",
                config_path,
            ),
            decisions,
        )
        result = json.loads(
            (self.project / ".forge" / "result.json").read_text(encoding="utf-8")
        )
        return exit_code, calls, result

    @staticmethod
    def _tree_hashes(root: Path):
        return {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def test_continue_after_max_iterations_creates_needs_continuation(self):
        exit_code, _, result = self._create_needs_continuation()
        self.assertEqual(exit_code, forge.EXIT_NEEDS_CONTINUATION)
        self.assertEqual(result["final_status"], "needs_continuation")
        self.assertEqual(result["schema_version"], forge.SCHEMA_VERSION)
        continuation = result["continuation"]
        self.assertEqual(continuation["source_run_id"], result["run_id"])
        self.assertEqual(
            continuation["continuation_chain_id"],
            result["continuation_chain_id"],
        )
        self.assertEqual(continuation["next_prompt"], "Finish exact feature.")
        self.assertEqual(continuation["acceptance_criteria"], ["Feature works", "Checks pass"])
        self.assertTrue(continuation["last_check_results"])
        self.assertEqual(continuation["repository_fingerprint"], result["repository_fingerprint"])
        self.assertEqual(continuation["chain_worker_calls"], 1)
        self.assertEqual(continuation["chain_full_check_suites"], 1)

    def test_resume_latest_creates_child_and_preserves_old_logs_bitwise(self):
        _, _, source_result = self._create_needs_continuation()
        source_directory = Path(source_result["run_directory"])
        before = self._tree_hashes(source_directory)
        context = forge.load_resume_context(self.project, "latest")
        self.assertEqual(context["source_run_id"], source_result["run_id"])

        exit_code, calls = self._run_operation(
            lambda: forge.resume_forge(self.project, "latest"),
            [
                forge.Decision(
                    status="done",
                    assessment="Continuation complete",
                    next_prompt=None,
                    acceptance_criteria=["Feature works", "Checks pass"],
                    risks=[],
                )
            ],
        )
        self.assertEqual(exit_code, forge.EXIT_DONE)
        child = json.loads(
            (self.project / ".forge" / "result.json").read_text(encoding="utf-8")
        )
        self.assertNotEqual(child["run_id"], source_result["run_id"])
        self.assertEqual(child["parent_run_id"], source_result["run_id"])
        self.assertEqual(
            child["continuation_chain_id"],
            source_result["continuation_chain_id"],
        )
        self.assertEqual(before, self._tree_hashes(source_directory))
        self.assertEqual([call["phase"] for call in calls], ["final"])

    def test_resume_transfers_prompt_acceptance_and_chain_counters(self):
        _, _, source = self._create_needs_continuation(
            next_prompt="Implement the exact inherited repair."
        )
        exit_code, _ = self._run_operation(
            lambda: forge.resume_forge(self.project, source["run_id"]),
            [
                forge.Decision(
                    status="done",
                    assessment="Done",
                    next_prompt=None,
                    acceptance_criteria=["Feature works", "Checks pass"],
                    risks=[],
                )
            ],
        )
        self.assertEqual(exit_code, forge.EXIT_DONE)
        child = json.loads(
            (self.project / ".forge" / "result.json").read_text(encoding="utf-8")
        )
        first_decision = json.loads(
            (Path(child["logs_path"]) / "01-decision.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            first_decision["next_prompt"],
            "Implement the exact inherited repair.",
        )
        self.assertEqual(
            first_decision["acceptance_criteria"],
            ["Feature works", "Checks pass"],
        )
        self.assertEqual(
            child["chain_worker_calls"],
            source["continuation"]["chain_worker_calls"] + 1,
        )
        self.assertEqual(
            child["chain_full_check_suites"],
            source["continuation"]["chain_full_check_suites"] + 1,
        )
        self.assertGreaterEqual(
            child["chain_elapsed_seconds"],
            source["continuation"]["chain_elapsed_seconds"],
        )

    def test_opus_limit_is_not_reset_by_resume(self):
        _, _, source = self._create_needs_continuation()
        source_directory = Path(source["run_directory"])
        source_run_path = source_directory / "run.json"
        source_result_path = source_directory / "result.json"
        run_payload = json.loads(source_run_path.read_text(encoding="utf-8"))
        run_payload["config"]["claude_escalation_enabled"] = True
        run_payload["config"]["claude_escalation_max_per_run"] = 1
        source_run_path.write_text(json.dumps(run_payload), encoding="utf-8")
        source["continuation"]["chain_premium_escalations"] = 1
        source["chain_premium_escalations"] = 1
        source["premium_claude_escalations_used"] = 1
        source_result_path.write_text(json.dumps(source), encoding="utf-8")
        (self.project / ".forge" / "result.json").write_text(
            json.dumps(source), encoding="utf-8"
        )

        exit_code, _ = self._run_operation(
            lambda: forge.resume_forge(self.project, source["run_id"]),
            [
                forge.Decision(
                    status="done",
                    assessment="Review standard worker progress",
                    next_prompt=None,
                    acceptance_criteria=["Checks pass"],
                    risks=[],
                )
            ],
            mode="escalate",
        )
        self.assertEqual(exit_code, forge.EXIT_DONE)
        child = json.loads(
            (self.project / ".forge" / "result.json").read_text(encoding="utf-8")
        )
        args = json.loads(self.args_file.read_text(encoding="utf-8"))
        self.assertIn("sonnet", args)
        self.assertNotIn("opus", args)
        self.assertEqual(child["chain_premium_escalations"], 1)
        self.assertEqual(child["run_premium_claude_escalations_used"], 0)
        rescue_routes = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in Path(child["logs_path"]).glob("*E*-worker-routing.json")
        ]
        self.assertTrue(rescue_routes)
        self.assertTrue(
            all(route["selected_model"] != "opus" for route in rescue_routes)
        )

    def test_unchanged_fingerprint_skips_general_architecture_review(self):
        _, _, source = self._create_needs_continuation()
        exit_code, calls = self._run_operation(
            lambda: forge.resume_forge(self.project, source["run_id"]),
            [
                forge.Decision(
                    status="done",
                    assessment="Done",
                    next_prompt=None,
                    acceptance_criteria=["Checks pass"],
                    risks=[],
                )
            ],
        )
        self.assertEqual(exit_code, forge.EXIT_DONE)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["phase"], "final")
        self.assertNotIn("architecture", calls[0]["prompt"].lower())

    def test_changed_fingerprint_requires_short_consistency_review(self):
        _, _, source = self._create_needs_continuation()
        (self.project / "external.txt").write_text("outside change", encoding="utf-8")
        exit_code, calls = self._run_operation(
            lambda: forge.resume_forge(self.project, source["run_id"]),
            [
                forge.Decision(
                    status="continue",
                    assessment="Original task remains valid",
                    next_prompt=source["continuation"]["next_prompt"],
                    acceptance_criteria=source["continuation"]["acceptance_criteria"],
                    risks=source["continuation"]["risks"],
                ),
                forge.Decision(
                    status="done",
                    assessment="Done after consistency review",
                    next_prompt=None,
                    acceptance_criteria=["Checks pass"],
                    risks=[],
                ),
            ],
        )
        self.assertEqual(exit_code, forge.EXIT_DONE)
        self.assertEqual([item["phase"] for item in calls], ["review", "final"])
        self.assertIn("RESUME CONSISTENCY REVIEW ONLY", calls[0]["prompt"])
        self.assertIn("ORIGINAL NEXT PROMPT", calls[0]["prompt"])
        self.assertIn("external.txt", calls[0]["prompt"])

    def test_error_max_turns_with_progress_and_green_checks_does_not_use_opus(self):
        worker = forge.WorkerResult(
            exit_code=1,
            summary="error_max_turns",
            raw_output="",
            duration_seconds=1,
            model="sonnet",
            effort="medium",
        )
        checks = [forge.CheckResult(command="tests", exit_code=0, output="OK")]
        reasons = forge.claude_escalation_reasons(
            worker=worker,
            checks=checks,
            failed_iterations=0,
            no_progress_count=0,
            progress_made=True,
            repeated_failure_count=0,
            escalations_used=0,
            config=forge.DEFAULT_CONFIG.copy(),
        )
        self.assertEqual(reasons, [])

    def test_technical_failure_stays_distinct_from_needs_continuation(self):
        config = self.continuation_config()
        config_path = self.root / "forge.failed.config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        exit_code, _ = self._run_operation(
            lambda: forge.run_forge(self.project, "Fail safely", config_path),
            [RuntimeError("simulated technical failure")],
        )
        result = json.loads(
            (self.project / ".forge" / "result.json").read_text(encoding="utf-8")
        )
        self.assertEqual(exit_code, forge.EXIT_FAILED)
        self.assertEqual(result["final_status"], "failed")
        self.assertIsNone(result["continuation"])

    def test_legacy_result_is_readable_but_not_resumable(self):
        legacy_project = self.root / "legacy project"
        source = legacy_project / ".forge" / "runs" / "legacy-run"
        source.mkdir(parents=True)
        legacy_result = {
            "run_id": "legacy-run",
            "goal": "Legacy goal",
            "final_status": "failed",
            "run_directory": str(source),
        }
        (source / "run.json").write_text(
            json.dumps({"run_id": "legacy-run", "goal": "Legacy goal", "config": {}}),
            encoding="utf-8",
        )
        (source / "result.json").write_text(json.dumps(legacy_result), encoding="utf-8")
        (legacy_project / ".forge" / "result.json").write_text(
            json.dumps(legacy_result), encoding="utf-8"
        )
        compatible = forge.read_result_compat(source / "result.json")
        self.assertEqual(compatible["schema_version"], 1)
        self.assertIsNone(compatible["continuation"])
        before_runs = sorted(path.name for path in (legacy_project / ".forge" / "runs").iterdir())
        exit_code = forge.resume_forge(legacy_project, "legacy-run")
        after_runs = sorted(path.name for path in (legacy_project / ".forge" / "runs").iterdir())
        self.assertEqual(exit_code, forge.EXIT_FAILED)
        self.assertEqual(before_runs, after_runs)


class EconomyPolicyTests(unittest.TestCase):
    def test_claude_auth_summary_omits_personal_fields(self):
        payload = {
            "loggedIn": True,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "subscriptionType": "max",
            "email": "private@example.com",
            "orgId": "private-org-id",
        }
        completed = subprocess.CompletedProcess(
            ["claude", "auth", "status"], 0, stdout=json.dumps(payload), stderr=""
        )
        with mock.patch.object(forge, "find_cli", return_value="claude"), mock.patch.object(
            forge.subprocess, "run", return_value=completed
        ):
            ok, summary = forge.claude_auth_status(strict=True)
        self.assertTrue(ok)
        self.assertNotIn("private@example.com", summary)
        self.assertNotIn("private-org-id", summary)
        self.assertIn('"subscriptionType": "max"', summary)

    def test_incremental_evidence_previews_only_changed_untracked_files(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            forge.ensure_git_repo(project)
            (project / "a.txt").write_text("first", encoding="utf-8")
            (project / "b.txt").write_text("stable", encoding="utf-8")
            baseline = forge.repo_manifest(project)
            (project / "a.txt").write_text("second", encoding="utf-8")
            current = forge.repo_manifest(project)
            evidence = forge.collect_repo_evidence(
                project,
                forge.DEFAULT_CONFIG.copy(),
                baseline=baseline,
                current_manifest=current,
            )
        self.assertIn("INCREMENTAL SINCE PREVIOUS REVIEW", evidence)
        self.assertIn("--- NEW FILE: a.txt ---", evidence)
        self.assertNotIn("--- NEW FILE: b.txt ---", evidence)

    def test_success_and_failure_check_context_is_bounded(self):
        config = forge.DEFAULT_CONFIG.copy()
        checks = [
            forge.CheckResult(command="ok", exit_code=0, output="x" * 5000),
            forge.CheckResult(command="bad", exit_code=1, output="y" * 10000),
        ]
        text_value = forge.checks_as_text(checks, config)
        self.assertLessEqual(len(text_value), config["max_checks_prompt_chars"] + 100)
        self.assertIn("skrátené", text_value)

    def test_goal_is_full_once_then_compact_for_codex_and_claude(self):
        config = forge.DEFAULT_CONFIG.copy()
        config["max_repeated_goal_chars"] = 80
        goal = "Long immutable goal. " * 100
        self.assertEqual(forge.compact_goal(goal, 1, config), goal)
        repeated = forge.compact_goal(goal, 2, config)
        self.assertIn(".forge/run.json", repeated)
        self.assertLess(len(repeated), len(goal))
        self.assertLessEqual(len(repeated), 230)

    def test_claude_escalation_is_bounded_and_reasoned(self):
        config = forge.DEFAULT_CONFIG.copy()
        worker = forge.WorkerResult(
            exit_code=7,
            summary="worker failed",
            raw_output="",
            duration_seconds=1,
            model="sonnet",
            effort="medium",
        )
        checks = [forge.CheckResult(command="tests", exit_code=1, output="failed")]
        reasons = forge.claude_escalation_reasons(
            worker=worker,
            checks=checks,
            failed_iterations=2,
            no_progress_count=1,
            progress_made=False,
            repeated_failure_count=2,
            escalations_used=0,
            config=config,
        )
        self.assertGreaterEqual(len(reasons), 2)
        blocked = forge.claude_escalation_reasons(
            worker=worker,
            checks=checks,
            failed_iterations=2,
            no_progress_count=1,
            progress_made=False,
            repeated_failure_count=2,
            escalations_used=1,
            config=config,
        )
        self.assertEqual(blocked, [])

    def test_codex_telemetry_keeps_counts_without_raw_events(self):
        raw = json.dumps({
            "type": "turn.completed",
            "model": "gpt-5.6-sol",
            "usage": {"input_tokens": 12, "output_tokens": 3},
        })
        telemetry = forge.extract_codex_telemetry(
            raw,
            phase="final",
            configured_model="gpt-5.6-sol",
            configured_effort="xhigh",
        )
        self.assertEqual(telemetry["resolved_model"], "gpt-5.6-sol")
        self.assertEqual(telemetry["usage_counts"]["input_count"], 12)
        self.assertFalse(telemetry["raw_events_stored"])


@unittest.skipUnless(os.name == "nt", "PowerShell wrapper test is Windows-only")
class WrapperContinuationTests(unittest.TestCase):
    def test_wrapper_invokes_one_resume_process_without_restart_loop(self):
        powershell = shutil.which("powershell.exe")
        self.assertIsNotNone(powershell)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project with spaces"
            project.mkdir()
            wrapper = root / "Start-ForgeAutonomous.ps1"
            shutil.copy2(STAGING / "Start-ForgeAutonomous.ps1", wrapper)
            config = forge.DEFAULT_CONFIG.copy()
            config["adaptive_orchestration"] = True
            config["adaptive_auto_supervisor"] = True
            (root / "forge.config.json").write_text(
                json.dumps(config), encoding="utf-8"
            )
            calls_path = root / "calls.jsonl"
            fake_forge = root / "forge.py"
            fake_forge.write_text(
                textwrap.dedent(
                    """
                    import json
                    import os
                    import sys
                    from pathlib import Path

                    args = sys.argv[1:]
                    with open(os.environ["FAKE_FORGE_CALLS"], "a", encoding="utf-8") as handle:
                        handle.write(json.dumps(args) + "\\n")
                    if args and args[0] == "doctor":
                        raise SystemExit(0)
                    if args and args[0] == "run-chain":
                        project = Path(args[args.index("--project") + 1])
                        forge_dir = project / ".forge"
                        forge_dir.mkdir(parents=True, exist_ok=True)
                        (forge_dir / "result.json").write_text(
                            json.dumps(
                                {
                                    "schema_version": 2,
                                    "run_id": "resume-source",
                                    "final_status": "needs_continuation",
                                }
                            ),
                            encoding="utf-8",
                        )
                        raise SystemExit(4)
                    raise SystemExit(9)
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["FAKE_FORGE_CALLS"] = str(calls_path)
            env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
            completed = subprocess.run(
                [
                    powershell,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(wrapper),
                    "-ProjectPath",
                    str(project),
                    "-ResumeLatest",
                    "-NoMonitor",
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=30,
                env=env,
            )
            calls = [
                json.loads(line)
                for line in calls_path.read_text(encoding="utf-8").splitlines()
            ]
        self.assertEqual(completed.returncode, forge.EXIT_NEEDS_CONTINUATION)
        self.assertEqual(sum(1 for call in calls if call and call[0] == "doctor"), 1)
        self.assertEqual(sum(1 for call in calls if call and call[0] == "run-chain"), 1)
        chain_call = next(call for call in calls if call and call[0] == "run-chain")
        self.assertIn("--resume-run-id", chain_call)
        self.assertEqual(sum(1 for call in calls if call and call[0] == "run"), 0)
        output = completed.stdout + completed.stderr
        self.assertIn("Nespustil sa ziadny genericky restart", output)
        self.assertIn("-ResumeRunId", output)


@unittest.skipUnless(os.name == "nt", "PowerShell monitor transition test is Windows-only")
class MonitorTests(unittest.TestCase):
    def test_monitor_follows_two_iterations_and_stops(self):
        powershell = shutil.which("powershell.exe")
        self.assertIsNotNone(powershell)
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "monitor project"
            (project / ".forge" / "logs").mkdir(parents=True)
            tracker = forge.StatusTracker(project, "Monitor goal", "monitor-run")
            tracker.set_phase(
                "claude_implementation",
                iteration=1,
                current_agent="Claude Code",
                message="Iteration one",
            )
            process = subprocess.Popen(
                [
                    powershell,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(STAGING / "Watch-Forge.ps1"),
                    "-Project",
                    str(project),
                    "-RefreshSeconds",
                    "1",
                    "-NoClear",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            time.sleep(1.3)
            tracker.set_phase(
                "automatic_checks",
                iteration=2,
                current_agent="Forge",
                message="Iteration two",
            )
            time.sleep(1.3)
            tracker.set_phase(
                "done",
                iteration=2,
                current_agent="Forge",
                message="Done",
                final_status="done",
            )
            output, _ = process.communicate(timeout=12)
        self.assertIn("Forge Live Monitor – Varianta 3", output)
        self.assertIn("KONTROLNÝ ZOZNAM PROJEKTU", output)
        self.assertIn("Claude práve:", output)
        self.assertIn("Aktuálny krok:", output)
        self.assertIn("100% HOTOVÉ", output)
        self.assertIn("Monitor skončil: done", output)

    def test_monitor_variant3_is_default_and_hides_technical_details(self):
        powershell = shutil.which("powershell.exe")
        self.assertIsNotNone(powershell)
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "apartmany plus"
            logs = project / ".forge" / "logs"
            logs.mkdir(parents=True)
            status = {
                "run_id": "variant3-run",
                "project": str(project),
                "goal": "Vytvor evidenciu nájomníkov.",
                "iteration": 1,
                "phase": "done",
                "phase_started_at": forge.utc_now(),
                "current_agent": "Forge",
                "current_tool": "Bash",
                "current_file": "tenants.py",
                "current_command": "python -m pytest",
                "last_visible_message": "Codex schválil výsledok.",
                "last_event_at": forge.utc_now(),
                "elapsed_seconds": 0,
                "final_status": "done",
            }
            (project / ".forge" / "status.json").write_text(
                json.dumps(status), encoding="utf-8"
            )
            (project / "SPEC.md").write_text(
                "# Apartmány Plus\n\n"
                "- [x] Základ aplikácie\n"
                "- [ ] Evidencia nájomníkov\n",
                encoding="utf-8",
            )
            (logs / "01-decision.json").write_text(
                json.dumps(
                    {
                        "status": "continue",
                        "assessment": "Implement tenant form.",
                        "next_prompt": "Pridaj nájomníka a priraď ho k apartmánu.",
                        "acceptance_criteria": [
                            "Formulár nájomníka funguje",
                            "Duplicitný e-mail je zablokovaný",
                        ],
                        "risks": [],
                    }
                ),
                encoding="utf-8",
            )
            (logs / "01-checks.json").write_text(
                json.dumps(
                    [
                        {"command": "lint", "exit_code": 0, "output": "OK"},
                        {"command": "tests", "exit_code": 0, "output": "OK"},
                    ]
                ),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    powershell,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(STAGING / "Watch-Forge.ps1"),
                    "-Project",
                    str(project),
                    "-NoClear",
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=10,
            )
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("Forge Live Monitor – Varianta 3", output)
        self.assertIn("50% HOTOVÉ", output)
        self.assertIn("KONTROLNÝ ZOZNAM PROJEKTU", output)
        self.assertIn("✓ Základ aplikácie", output)
        self.assertIn("◉ Evidencia nájomníkov", output)
        self.assertIn("Codex zadal:", output)
        self.assertIn("Pridaj nájomníka a priraď ho k apartmánu.", output)
        self.assertIn("Claude práve:", output)
        self.assertIn("Aktuálny krok:", output)
        self.assertIn("Posledný výsledok:", output)
        self.assertIn("Prešlo všetkých 2 z 2 kontrol.", output)
        self.assertIn("Nasleduje:", output)
        self.assertIn("Váš zásah: NIE JE POTREBNÝ", output)
        self.assertNotIn("TECHNICKÉ PODROBNOSTI", output)
        self.assertNotIn("Príkaz:", output)

    def test_monitor_variant3_shows_adaptive_packet_profile_tier_and_budget(self):
        powershell = shutil.which("powershell.exe")
        self.assertIsNotNone(powershell)
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "adaptive monitor"
            forge_dir = project / ".forge"
            logs = forge_dir / "logs"
            logs.mkdir(parents=True)
            status = {
                "run_id": "adaptive-monitor-run",
                "project": str(project),
                "goal": "Build safe app.",
                "iteration": 1,
                "phase": "done",
                "phase_started_at": forge.utc_now(),
                "current_agent": "Forge",
                "current_tool": "",
                "current_file": "",
                "current_command": "",
                "last_visible_message": "Packet verified.",
                "last_event_at": forge.utc_now(),
                "heartbeat_at": forge.utc_now(),
                "heartbeat_sequence": 3,
                "model_polling": False,
                "elapsed_seconds": 1,
                "final_status": "done",
                "packet_total": 2,
                "packet_completed": 1,
                "active_packet_id": "packet-002",
                "active_packet_title": "Evidencia nájomníkov",
                "worker_profile": "standard",
                "worker_profile_reason": "Routine CRUD implementation.",
                "check_tier": "targeted",
                "remaining_chain_budget": {
                    "worker_calls": 8,
                    "child_runs": 3,
                },
                "premium_uses": 0,
            }
            (forge_dir / "status.json").write_text(
                json.dumps(status), encoding="utf-8"
            )
            (forge_dir / "project-plan.json").write_text(
                json.dumps(
                    {
                        "work_packets": [
                            {"title": "Základ aplikácie", "status": "completed"},
                            {
                                "title": "Evidencia nájomníkov",
                                "status": "in_progress",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    powershell,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(STAGING / "Watch-Forge.ps1"),
                    "-Project",
                    str(project),
                    "-NoClear",
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=10,
            )
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("Základ aplikácie", output)
        self.assertIn("Evidencia nájomníkov", output)
        self.assertIn("Aktívny pracovný balík:", output)
        self.assertIn("Profil pracovníka: standard", output)
        self.assertIn("Routine CRUD implementation.", output)
        self.assertIn("Úroveň kontroly: targeted", output)
        self.assertIn("Zostávajúci bezpečný limit:", output)
        self.assertIn("worker_calls: 8", output)
        self.assertNotIn("model polling", output.lower())

    def test_monitor_redacts_status_values(self):
        powershell = shutil.which("powershell.exe")
        self.assertIsNotNone(powershell)
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "redaction project"
            forge_dir = project / ".forge"
            (forge_dir / "logs").mkdir(parents=True)
            status = {
                "run_id": "redaction-run",
                "project": str(project),
                "goal": "Safe goal",
                "iteration": 1,
                "phase": "done",
                "phase_started_at": forge.utc_now(),
                "current_agent": "Forge",
                "current_tool": "Bash",
                "current_file": "safe.txt",
                "current_command": "TOKEN=very-secret-value command",
                "last_visible_message": "password=hunter2",
                "last_event_at": forge.utc_now(),
                "elapsed_seconds": 0,
                "final_status": "done",
            }
            (forge_dir / "status.json").write_text(
                json.dumps(status), encoding="utf-8"
            )
            completed = subprocess.run(
                [
                    powershell,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(STAGING / "Watch-Forge.ps1"),
                    "-Project",
                    str(project),
                    "-NoClear",
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=10,
            )
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0)
        self.assertNotIn("very-secret-value", output)
        self.assertNotIn("hunter2", output)
        self.assertIn("[REDACTED]", output)


if __name__ == "__main__":
    unittest.main()
