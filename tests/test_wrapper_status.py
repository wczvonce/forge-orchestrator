from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WATCH = ROOT / "Watch-Forge.ps1"
WRAPPER = ROOT / "Start-ForgeAutonomous.ps1"


def utc_text(*, seconds_ago: int = 0) -> str:
    value = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    return value.isoformat().replace("+00:00", "Z")


@unittest.skipUnless(os.name == "nt", "PowerShell UX tests are Windows-only")
class MonitorTerminationUxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.powershell = shutil.which("powershell.exe")
        self.assertIsNotNone(self.powershell)
        self.temp = tempfile.TemporaryDirectory()
        self.project = Path(self.temp.name) / "forge status O'Brien project"
        (self.project / ".forge" / "logs").mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_status(
        self,
        *,
        run_id: str,
        phase: str = "needs_continuation",
        final_status: str = "needs_continuation",
        logs_path: str | None = None,
    ) -> None:
        status = {
            "schema_version": 4,
            "run_id": run_id,
            "run_started_at": utc_text(seconds_ago=240),
            "project": str(self.project),
            "goal": "Build the app.",
            "iteration": 1,
            "phase": phase,
            "phase_started_at": utc_text(seconds_ago=240),
            "current_agent": "Forge",
            "current_tool": "",
            "current_file": "",
            "current_command": "",
            "last_visible_message": "Forge reached a bounded stop.",
            "last_event_at": utc_text(seconds_ago=240),
            "heartbeat_at": utc_text(seconds_ago=240),
            "elapsed_seconds": 240,
            "final_status": final_status,
            "activity_state": "terminal",
            "needs_human": True,
            "packet_total": 4,
            "packet_completed": 1,
            "active_packet_id": "WP-02",
            "active_packet_title": "Mobile shell",
            "remaining_chain_budget": {
                "child_runs": 5,
                "worker_calls": 14,
            },
            "premium_uses": 0,
            "logs_path": logs_path or str(self.project / ".forge" / "logs"),
        }
        (self.project / ".forge" / "status.json").write_text(
            json.dumps(status), encoding="utf-8"
        )

    def write_result(
        self,
        *,
        run_id: str,
        reason: str,
        automatic: bool,
        final_status: str = "needs_continuation",
        chain_budget_kind: str = "child",
    ) -> None:
        result = {
            "schema_version": 4,
            "run_id": run_id,
            "final_status": final_status,
            "stop_reason_code": reason,
            "automatic_resume_allowed": automatic,
            "final_message": f"Structured stop: {reason}",
        }
        if reason == "chain_budget_exhausted":
            budgets = {
                "max_child_runs": 2,
                "max_codex_calls": 4,
                "max_worker_calls": 4,
                "max_elapsed_seconds": 120,
                "max_full_check_suites": 2,
                "max_premium_escalations": 1,
                "max_no_progress_events": 2,
            }
            result.update(
                {
                    "base_chain_budgets": budgets,
                    "effective_chain_budgets": budgets,
                    "budget_extension_count": 0,
                    "chain_child_runs": (
                        budgets["max_child_runs"]
                        if chain_budget_kind == "child"
                        else 0
                    ),
                    "chain_codex_calls": 0,
                    "chain_worker_calls": 0,
                    "chain_elapsed_seconds": 0,
                    "chain_full_check_suites": 0,
                    "chain_premium_escalations": (
                        budgets["max_premium_escalations"]
                        if chain_budget_kind == "premium"
                        else 0
                    ),
                    "chain_no_progress_events": 0,
                }
            )
        (self.project / ".forge" / "result.json").write_text(
            json.dumps(result), encoding="utf-8"
        )

    def write_run(
        self,
        *,
        run_id: str,
        mode: str = "economy-safe-strict",
        security_profile: str = "strict",
        stored_run_id: str | None = None,
        unattended_requires_sandbox: bool = True,
    ) -> None:
        run_directory = self.project / ".forge" / "runs" / run_id
        run_directory.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": 4,
            "run_id": stored_run_id or run_id,
            "config": {
                "mode": mode,
                "security_profile": security_profile,
                "unattended_requires_sandbox": unattended_requires_sandbox,
            },
        }
        (run_directory / "run.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )

    def write_supervisor(
        self,
        *,
        status: str,
        exit_code: int | None = None,
        seconds_ago: int = 0,
    ) -> None:
        payload = {
            "schema_version": 4,
            "project": str(self.project),
            "status": status,
            "started_at": utc_text(seconds_ago=seconds_ago),
            "updated_at": utc_text(seconds_ago=seconds_ago),
        }
        if exit_code is not None:
            payload["exit_code"] = exit_code
        (self.project / ".forge" / "chain-supervisor.json").write_text(
            json.dumps(payload),
            encoding="utf-8",
        )

    def run_monitor(
        self,
        timeout: int = 12,
        *,
        not_before: str | None = None,
        supervisor_grace: int = 90,
    ) -> subprocess.CompletedProcess[str]:
        command = [
                self.powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(WATCH),
                "-Project",
                str(self.project),
                "-RefreshSeconds",
                "1",
                "-NoClear",
                "-SupervisorGraceSeconds",
                str(supervisor_grace),
            ]
        if not_before is not None:
            command.extend(["-NotBeforeUtc", not_before])
        return subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
        )

    def test_packet_attempt_exhaustion_is_not_global_budget_or_resume(self) -> None:
        self.write_status(run_id="packet-stop")
        self.write_result(
            run_id="packet-stop",
            reason="packet_attempts_exhausted",
            automatic=False,
        )

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("Vyčerpal sa počet pokusov aktívneho packetu", output)
        self.assertIn("globálny chain budget môže mať stále rezervu", output)
        self.assertNotIn("Resume príkaz:", output)
        self.assertNotIn("Start-ForgeAutonomous.ps1' -ProjectPath", output)
        self.assertIn("nejde o hang", output)

    def test_matching_terminal_result_overrides_stale_review_status(self) -> None:
        self.write_status(
            run_id="stale-status",
            phase="codex_review",
            final_status="",
        )
        self.write_result(
            run_id="stale-status",
            reason="packet_attempts_exhausted",
            automatic=False,
        )

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("Monitor skončil: needs_continuation", output)
        self.assertIn("nejde o hang", output)
        self.assertNotIn("Resume príkaz:", output)

    def test_chain_budget_exhaustion_offers_only_exact_manual_resume(self) -> None:
        self.write_status(run_id="chain-stop")
        self.write_result(
            run_id="chain-stop",
            reason="chain_budget_exhausted",
            automatic=False,
        )
        self.write_supervisor(status="needs_continuation", exit_code=4)
        self.write_run(run_id="chain-stop")

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("GLOBÁLNOM CHAIN LIMITE", output)
        self.assertIn("Resume príkaz:", output)
        self.assertIn("-ResumeRunId 'chain-stop'", output)
        self.assertIn("-Mode 'Strict'", output)
        self.assertIn("O''Brien project'", output)
        self.assertNotIn("-ProjectPath '" + str(self.project) + "'", output)
        self.assertNotIn("vyčerpal svoje pokusy", output)
        resume_command = next(
            line
            for line in output.splitlines()
            if line.startswith("& ") and " -ResumeRunId " in line
        )
        parse_env = os.environ.copy()
        parse_env["FORGE_RESUME_COMMAND"] = resume_command
        parsed = subprocess.run(
            [
                self.powershell,
                "-NoProfile",
                "-Command",
                (
                    "$tokens=$null; $errors=$null; "
                    "[System.Management.Automation.Language.Parser]::ParseInput("
                    "$env:FORGE_RESUME_COMMAND, [ref]$tokens, [ref]$errors) > $null; "
                    "if ($errors.Count) { $errors | ForEach-Object { $_.ToString() }; exit 1 }"
                ),
            ],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=10,
            env=parse_env,
        )
        self.assertEqual(parsed.returncode, 0, msg=parsed.stdout + parsed.stderr)

    def test_manual_resume_waits_for_terminal_supervisor_exit_four(self) -> None:
        run_id = "chain-waits-for-supervisor"
        self.write_status(run_id=run_id)
        self.write_result(
            run_id=run_id,
            reason="chain_budget_exhausted",
            automatic=False,
        )
        self.write_run(run_id=run_id)
        self.write_supervisor(status="running")
        command = [
            self.powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(WATCH),
            "-Project",
            str(self.project),
            "-RefreshSeconds",
            "1",
            "-NoClear",
        ]
        process = subprocess.Popen(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1.4)
        self.write_supervisor(status="needs_continuation", exit_code=4)
        stdout, stderr = process.communicate(timeout=12)
        output = stdout + stderr

        self.assertEqual(process.returncode, 0, msg=output)
        self.assertIn("ČAKÁM NA UKONČENIE SUPERVISORA", output)
        self.assertIn("Resume príkaz:", output)
        self.assertIn(f"-ResumeRunId '{run_id}'", output)

    def test_premium_only_chain_stop_does_not_offer_a_dead_resume(self) -> None:
        self.write_status(run_id="premium-only-stop")
        self.write_result(
            run_id="premium-only-stop",
            reason="chain_budget_exhausted",
            automatic=False,
            chain_budget_kind="premium",
        )
        self.write_supervisor(status="needs_continuation", exit_code=4)
        self.write_run(run_id="premium-only-stop")

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("ne-prémiový budget tranche", output)
        self.assertNotIn("Resume príkaz:", output)

    def test_resume_mode_is_derived_from_matching_source_run(self) -> None:
        cases = (
            ("strict-source", "economy-safe-strict", "strict", "Strict"),
            ("max-source", "economy-max", "balanced", "EconomyMax"),
            ("android-source", "economy-safe-android", "balanced", "Android"),
        )
        for run_id, stored_mode, security_profile, wrapper_mode in cases:
            with self.subTest(stored_mode=stored_mode):
                self.write_status(run_id=run_id)
                self.write_result(
                    run_id=run_id,
                    reason="chain_budget_exhausted",
                    automatic=False,
                )
                self.write_supervisor(status="needs_continuation", exit_code=4)
                self.write_run(
                    run_id=run_id,
                    mode=stored_mode,
                    security_profile=security_profile,
                )
                completed = self.run_monitor()
                output = completed.stdout + completed.stderr

                self.assertEqual(completed.returncode, 0, msg=output)
                self.assertIn("Resume príkaz:", output)
                self.assertIn(f"-ResumeRunId '{run_id}'", output)
                self.assertIn(f"-Mode '{wrapper_mode}'", output)

    def test_unrecognized_or_mismatched_source_run_never_prints_resume(self) -> None:
        cases = (
            ("legacy-balanced", "economy-safe", "balanced", "legacy-balanced"),
            ("mismatched-id", "economy-safe-strict", "strict", "other-run"),
        )
        for run_id, stored_mode, security_profile, stored_run_id in cases:
            with self.subTest(run_id=run_id):
                self.write_status(run_id=run_id)
                self.write_result(
                    run_id=run_id,
                    reason="chain_budget_exhausted",
                    automatic=False,
                )
                self.write_supervisor(status="needs_continuation", exit_code=4)
                self.write_run(
                    run_id=run_id,
                    mode=stored_mode,
                    security_profile=security_profile,
                    stored_run_id=stored_run_id,
                )
                completed = self.run_monitor()
                output = completed.stdout + completed.stderr

                self.assertEqual(completed.returncode, 0, msg=output)
                self.assertNotIn("Resume príkaz:", output)
                self.assertNotIn(" -ResumeRunId ", output)
                self.assertIn("config.mode/security_profile", output)

    def test_auto_resumable_child_does_not_close_monitor_or_offer_resume(self) -> None:
        self.write_status(run_id="child-one")
        self.write_result(
            run_id="child-one",
            reason="next_packet_ready",
            automatic=True,
        )
        self.write_supervisor(status="running")
        process = subprocess.Popen(
            [
                self.powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(WATCH),
                "-Project",
                str(self.project),
                "-RefreshSeconds",
                "1",
                "-NoClear",
            ],
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1.4)
        self.write_status(
            run_id="child-two",
            phase="done",
            final_status="done",
        )
        self.write_result(
            run_id="child-two",
            reason="completed",
            automatic=False,
            final_status="done",
        )
        stdout, stderr = process.communicate(timeout=12)
        output = stdout + stderr

        self.assertEqual(process.returncode, 0, msg=output)
        self.assertIn("AUTOMATICKÉ POKRAČOVANIE", output)
        self.assertIn("Monitor skončil: done", output)
        self.assertNotIn("Resume príkaz:", output)

    def test_failed_supervisor_is_not_shown_as_automatic_continuation(self) -> None:
        self.write_status(run_id="failed-supervisor")
        self.write_result(
            run_id="failed-supervisor",
            reason="next_packet_ready",
            automatic=True,
        )
        self.write_supervisor(status="failed", exit_code=1)

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("SUPERVISOR SA ZASTAVIL", output)
        self.assertIn("Monitor skončil: failed", output)
        self.assertNotIn("Resume príkaz:", output)

    def test_stale_running_supervisor_is_not_an_infinite_wait(self) -> None:
        self.write_status(run_id="stale-supervisor")
        self.write_result(
            run_id="stale-supervisor",
            reason="next_packet_ready",
            automatic=True,
        )
        self.write_supervisor(status="running", seconds_ago=240)

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("SUPERVISOR NEREAGUJE", output)
        self.assertIn("Monitor skončil: failed", output)
        self.assertNotIn("Resume príkaz:", output)

    def test_terminal_supervisor_is_authoritative_without_status(self) -> None:
        self.write_supervisor(status="failed", exit_code=1)

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("SUPERVISOR SA ZASTAVIL", output)
        self.assertIn("Monitor skončil: failed", output)

    def test_terminal_supervisor_is_authoritative_with_malformed_status(self) -> None:
        (self.project / ".forge" / "status.json").write_text(
            "{not-json",
            encoding="utf-8",
        )
        self.write_supervisor(status="failed", exit_code=1)

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("SUPERVISOR SA ZASTAVIL", output)
        self.assertIn("Monitor skončil: failed", output)

    def test_terminal_supervisor_overrides_stale_nonterminal_child_status(self) -> None:
        self.write_status(
            run_id="crashed-child",
            phase="claude_implementation",
            final_status="",
        )
        self.write_supervisor(status="failed", exit_code=1)

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("SUPERVISOR SA ZASTAVIL", output)
        self.assertIn("Monitor skončil: failed", output)

    def test_stale_running_supervisor_with_nonterminal_child_fails_closed(self) -> None:
        self.write_status(
            run_id="dead-running-child",
            phase="claude_implementation",
            final_status="",
        )
        self.write_supervisor(status="running", seconds_ago=240)

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("SUPERVISOR NEREAGUJE", output)
        self.assertIn("Monitor skončil: failed", output)

    def test_terminal_done_supervisor_overrides_stale_auto_child_pointer(self) -> None:
        self.write_status(run_id="stale-auto")
        self.write_result(
            run_id="stale-auto",
            reason="next_packet_ready",
            automatic=True,
        )
        self.write_supervisor(status="done", exit_code=0)

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("FORGE SUPERVISOR DOKONČIL CHAIN", output)
        self.assertIn("Monitor skončil: done", output)
        self.assertNotIn("Váš zásah ani manuálny Resume nie sú potrebné", output)

    def test_missing_supervisor_with_stale_auto_child_fails_closed(self) -> None:
        self.write_status(run_id="orphan-auto")
        self.write_result(
            run_id="orphan-auto",
            reason="next_packet_ready",
            automatic=True,
        )

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("SUPERVISOR NEREAGUJE", output)
        self.assertIn("Monitor skončil: failed", output)
        self.assertNotIn("Váš zásah ani manuálny Resume nie sú potrebné", output)

    def test_launch_generation_ignores_old_terminal_pointers(self) -> None:
        self.write_status(run_id="old-run", phase="done", final_status="done")
        self.write_result(
            run_id="old-run",
            reason="completed",
            automatic=False,
            final_status="done",
        )
        self.write_supervisor(status="done", exit_code=0, seconds_ago=240)
        not_before = utc_text()
        command = [
            self.powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(WATCH),
            "-Project",
            str(self.project),
            "-RefreshSeconds",
            "1",
            "-NoClear",
            "-NotBeforeUtc",
            not_before,
        ]
        process = subprocess.Popen(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1.4)
        self.write_status(run_id="new-run", phase="done", final_status="done")
        self.write_result(
            run_id="new-run",
            reason="completed",
            automatic=False,
            final_status="done",
        )
        self.write_supervisor(status="done", exit_code=0)
        stdout, stderr = process.communicate(timeout=12)
        output = stdout + stderr

        self.assertEqual(process.returncode, 0, msg=output)
        self.assertIn("Monitor skončil: done", output)
        self.assertNotIn("Beh: old-run", output)

    def test_mixed_premium_and_extensible_exhaustion_offers_no_resume(self) -> None:
        run_id = "mixed-budget-stop"
        self.write_status(run_id=run_id)
        self.write_result(
            run_id=run_id,
            reason="chain_budget_exhausted",
            automatic=False,
            chain_budget_kind="child",
        )
        result_path = self.project / ".forge" / "result.json"
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        payload["chain_premium_escalations"] = payload[
            "effective_chain_budgets"
        ]["max_premium_escalations"]
        result_path.write_text(json.dumps(payload), encoding="utf-8")
        self.write_supervisor(status="needs_continuation", exit_code=4)
        self.write_run(run_id=run_id)

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertNotIn("Resume príkaz:", output)
        self.assertIn("ne-prémiový budget tranche", output)

    def test_current_result_routing_requires_native_schema_and_boolean_types(self) -> None:
        for field, invalid_value in (
            ("schema_version", "4"),
            ("automatic_resume_allowed", 0),
            ("automatic_resume_allowed", "false"),
        ):
            with self.subTest(field=field, invalid_value=invalid_value):
                run_id = f"bad-type-{field}-{str(invalid_value).lower()}"
                self.write_status(run_id=run_id)
                self.write_result(
                    run_id=run_id,
                    reason="chain_budget_exhausted",
                    automatic=False,
                )
                result_path = self.project / ".forge" / "result.json"
                payload = json.loads(result_path.read_text(encoding="utf-8"))
                payload[field] = invalid_value
                result_path.write_text(json.dumps(payload), encoding="utf-8")
                self.write_run(run_id=run_id)

                completed = self.run_monitor()
                output = completed.stdout + completed.stderr

                self.assertEqual(completed.returncode, 0, msg=output)
                self.assertNotIn("Resume príkaz:", output)
                self.assertIn("invalid_result_termination", output)

    def test_wsl_run_scoped_log_path_is_translated_back_to_windows(self) -> None:
        drive = self.project.drive.rstrip(":").lower()
        relative = self.project.resolve().as_posix()[3:]
        wsl_logs = f"/mnt/{drive}/{relative}/.forge/logs"
        self.write_status(
            run_id="wsl-run",
            phase="done",
            final_status="done",
            logs_path=wsl_logs,
        )
        decision_path = self.project / ".forge" / "logs" / "01-decision.json"
        decision_path.write_text(
            json.dumps(
                {
                    "status": "continue",
                    "next_prompt": "Read this WSL run-scoped decision.",
                    "acceptance_criteria": [],
                    "risks": [],
                }
            ),
            encoding="utf-8",
        )

        completed = self.run_monitor()
        output = completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("Read this WSL run-scoped decision.", output)


class WrapperSafetyContractTests(unittest.TestCase):
    def run_resume_eligibility_function(
        self,
        payload: dict,
        *,
        exit_code: int,
        requested_run_id: str = "source-run",
    ) -> subprocess.CompletedProcess[str]:
        powershell = shutil.which("powershell.exe")
        self.assertIsNotNone(powershell)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fake_cli = root / "fake_eligibility.py"
        fake_cli.write_text(
            "\n".join(
                [
                    "import os",
                    "raise_code = int(os.environ['FORGE_FAKE_EXIT'])",
                    "print(os.environ['FORGE_FAKE_PAYLOAD'])",
                    "raise SystemExit(raise_code)",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        harness = root / "eligibility_harness.ps1"
        harness.write_text(
            "\n".join(
                [
                    "Set-StrictMode -Version Latest",
                    "$ErrorActionPreference = 'Stop'",
                    "$tokens = $null",
                    "$parseErrors = $null",
                    "$ast = [System.Management.Automation.Language.Parser]::ParseFile(",
                    "  $env:FORGE_WRAPPER_SCRIPT, [ref]$tokens, [ref]$parseErrors",
                    ")",
                    "if ($parseErrors.Count) { throw 'Wrapper parser error.' }",
                    "$wanted = @('Test-JsonBoolean', 'Test-JsonInteger', 'Assert-ResumeEligibility')",
                    "foreach ($name in $wanted) {",
                    "  $nodes = @($ast.FindAll({",
                    "    param($node)",
                    "    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and",
                    "      $node.Name -ceq $name",
                    "  }, $true))",
                    "  if ($nodes.Count -ne 1) { throw \"Missing function: $name\" }",
                    "  Invoke-Expression $nodes[0].Extent.Text",
                    "}",
                    "$ForgeScript = 'ignored-forge.py'",
                    "$UseStrictWslRuntime = $true",
                    "$python = [pscustomobject]@{",
                    "  File = $env:FORGE_TEST_PYTHON",
                    "  PrefixArgs = @($env:FORGE_FAKE_CLI)",
                    "  ForgeScript = 'ignored-forge.py'",
                    "}",
                    "Assert-ResumeEligibility `",
                    "  -Python $python `",
                    "  -Project 'C:\\safe-project' `",
                    "  -RequestedRunId $env:FORGE_REQUESTED_RUN_ID `",
                    "  -SupervisorConfig 'C:\\strict.json'",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["FORGE_WRAPPER_SCRIPT"] = str(WRAPPER)
        env["FORGE_TEST_PYTHON"] = sys.executable
        env["FORGE_FAKE_CLI"] = str(fake_cli)
        env["FORGE_FAKE_PAYLOAD"] = json.dumps(payload)
        env["FORGE_FAKE_EXIT"] = str(exit_code)
        env["FORGE_REQUESTED_RUN_ID"] = requested_run_id
        return subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(harness),
            ],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=20,
            env=env,
        )

    def test_default_economy_safe_declares_audited_wsl_strict_route(self) -> None:
        text = WRAPPER.read_text(encoding="utf-8")
        self.assertIn(
            '$UseStrictWslRuntime = $Mode -in @("EconomySafe", "Strict")',
            text,
        )
        self.assertIn('"forge_adaptive.py"', text)
        self.assertIn('"forge_reports.py"', text)
        self.assertIn('"/usr/bin/true"', text)
        self.assertIn("Assert-StrictWslProjectSandbox", text)
        self.assertIn("allowWrite = @($AllowedWslPath, $DeniedWslPath)", text)
        self.assertIn("denyWrite = @($DeniedWslPath)", text)
        self.assertIn("$DeniedExitCode -eq 0", text)
        self.assertIn('"--config", $RuntimeConfigPath', text)
        self.assertIn("Assert-ResumeEligibility", text)
        self.assertIn('"resume-eligibility"', text)
        self.assertIn('"bounded_final_review_recovery"', text)
        self.assertIn('"extend_chain_budget_one_tranche"', text)
        self.assertIn("$Eligibility.state_mutated -ne $false", text)
        self.assertIn("[int]$Eligibility.model_calls_made -ne 0", text)
        self.assertIn("$SelectedResumeRunId = Assert-ResumeEligibility", text)
        self.assertIn("-NotBeforeUtc", text)
        self.assertNotIn("Assert-StrictResumeSource", text)

    @unittest.skipUnless(os.name == "nt", "PowerShell JSON contract tests are Windows-only")
    def test_resume_eligibility_requires_native_json_types(self) -> None:
        valid = {
            "schema_version": 4,
            "eligible": True,
            "source_run_id": "source-run",
            "source_stop_reason_code": "reviewer_continue",
            "source_automatic_resume_allowed": True,
            "action": "validated_exact_resume",
            "state_mutated": False,
            "model_calls_made": 0,
            "supervisor_config_enforced": True,
            "effective_security_profile": "strict",
        }
        accepted = self.run_resume_eligibility_function(valid, exit_code=0)
        self.assertEqual(
            accepted.returncode,
            0,
            msg=accepted.stdout + accepted.stderr,
        )

        for field, invalid_value in (
            ("schema_version", "4"),
            ("eligible", "true"),
            ("source_run_id", 7),
            ("source_stop_reason_code", 7),
            ("state_mutated", 0),
            ("model_calls_made", "0"),
            ("supervisor_config_enforced", 1),
        ):
            with self.subTest(field=field):
                malformed = dict(valid)
                malformed[field] = invalid_value
                rejected = self.run_resume_eligibility_function(
                    malformed,
                    exit_code=0,
                )
                self.assertNotEqual(rejected.returncode, 0)

        latest = self.run_resume_eligibility_function(
            valid,
            exit_code=0,
            requested_run_id="latest",
        )
        self.assertEqual(latest.returncode, 0, msg=latest.stdout + latest.stderr)
        self.assertIn("source-run", latest.stdout)

    @unittest.skipUnless(os.name == "nt", "PowerShell JSON contract tests are Windows-only")
    def test_rejected_eligibility_preserves_reason_without_success_fields(self) -> None:
        rejected = self.run_resume_eligibility_function(
            {
                "schema_version": 4,
                "eligible": False,
                "reason_code": "resume_validation_failed",
            },
            exit_code=1,
        )
        output = rejected.stdout + rejected.stderr
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("resume_validation_failed", output)
        self.assertNotIn("chyba povinne pole", output)

    @unittest.skipUnless(os.name == "nt", "PowerShell parser test is Windows-only")
    def test_powershell_scripts_parse_without_errors(self) -> None:
        powershell = shutil.which("powershell.exe")
        self.assertIsNotNone(powershell)
        for script in (WRAPPER, WATCH):
            command = (
                "$errors=$null; "
                f"[System.Management.Automation.Language.Parser]::ParseFile('{script}', "
                "[ref]$null, [ref]$errors) > $null; "
                "if ($errors.Count) { $errors | ForEach-Object { $_.ToString() }; exit 1 }"
            )
            completed = subprocess.run(
                [powershell, "-NoProfile", "-Command", command],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(
                completed.returncode,
                0,
                msg=completed.stdout + completed.stderr,
            )

    @unittest.skipUnless(os.name == "nt", "DrvFS canary test is Windows-only")
    def test_project_drvfs_canary_enforces_exact_write_boundary_without_model(self) -> None:
        powershell = shutil.which("powershell.exe")
        wsl = shutil.which("wsl.exe")
        self.assertIsNotNone(powershell)
        if wsl is None:
            self.skipTest("wsl.exe is unavailable")
        availability = subprocess.run(
            [
                wsl,
                "-d",
                "Ubuntu-24.04",
                "-u",
                "forge",
                "--",
                "/usr/bin/env",
                "PATH=/home/forge/.local/bin:/usr/local/bin:/usr/bin:/bin",
                "/home/forge/.local/bin/srt",
                "--version",
            ],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=15,
        )
        if availability.returncode != 0:
            self.skipTest("audited WSL SRT runtime is unavailable")

        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "DrvFS canary O'Brien"
            project.mkdir()
            harness = Path(temporary) / "invoke-canary.ps1"
            harness.write_text(
                "\n".join(
                    [
                        "Set-StrictMode -Version Latest",
                        "$ErrorActionPreference = 'Stop'",
                        "$tokens = $null",
                        "$parseErrors = $null",
                        "$ast = [System.Management.Automation.Language.Parser]::ParseFile(",
                        "  $env:FORGE_WRAPPER_SCRIPT, [ref]$tokens, [ref]$parseErrors",
                        ")",
                        "if ($parseErrors.Count) { throw 'Wrapper parser error.' }",
                        "$wanted = @(",
                        "  'Invoke-StrictWslProbe',",
                        "  'Convert-ToStrictWslPath',",
                        "  'Assert-StrictWslProjectSandbox'",
                        ")",
                        "foreach ($name in $wanted) {",
                        "  $nodes = @($ast.FindAll({",
                        "    param($node)",
                        "    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and",
                        "      $node.Name -ceq $name",
                        "  }, $true))",
                        "  if ($nodes.Count -ne 1) { throw \"Missing function: $name\" }",
                        "  Invoke-Expression $nodes[0].Extent.Text",
                        "}",
                        "$StrictWslDistribution = 'Ubuntu-24.04'",
                        "$StrictWslUser = 'forge'",
                        "$StrictWslPath = '/home/forge/.local/bin:/usr/local/bin:/usr/bin:/bin'",
                        "$wsl = (Get-Command wsl.exe -ErrorAction Stop).Source",
                        "$project = (Get-Item -LiteralPath $env:FORGE_CANARY_PROJECT).FullName",
                        "$runtimeProject = Convert-ToStrictWslPath -WslExecutable $wsl -WindowsPath $project",
                        "Assert-StrictWslProjectSandbox `",
                        "  -WslExecutable $wsl `",
                        "  -WindowsProjectPath $project `",
                        "  -WslProjectPath $runtimeProject `",
                        "  -WslPython '/usr/bin/python3'",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["FORGE_WRAPPER_SCRIPT"] = str(WRAPPER)
            env["FORGE_CANARY_PROJECT"] = str(project)
            completed = subprocess.run(
                [
                    powershell,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(harness),
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=45,
                env=env,
            )

            self.assertEqual(
                completed.returncode,
                0,
                msg=completed.stdout + completed.stderr,
            )
            self.assertFalse(
                list((project / ".forge").glob("wrapper-srt-canary-*")),
                "Canary must clean every temporary sentinel/settings file.",
            )


@unittest.skipUnless(os.name == "nt", "PowerShell wrapper tests are Windows-only")
class WrapperTerminationUxTests(unittest.TestCase):
    def run_fake_wrapper(
        self,
        reason: str,
        *,
        schema_value: object = 4,
        automatic_value: object = False,
    ) -> subprocess.CompletedProcess[str]:
        powershell = shutil.which("powershell.exe")
        self.assertIsNotNone(powershell)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        project = root / "project with spaces"
        project.mkdir()
        shutil.copy2(WRAPPER, root / WRAPPER.name)
        shutil.copy2(
            ROOT / "forge.max-economy.config.json",
            root / "forge.max-economy.config.json",
        )
        (root / "srt.cmd").write_text("@exit /b 0\r\n", encoding="utf-8")
        (root / "forge.py").write_text(
            "\n".join(
                [
                    "import json, os, sys",
                    "from pathlib import Path",
                    "args = sys.argv[1:]",
                    "if args and args[0] == 'doctor': raise SystemExit(0)",
                    "if args and args[0] == 'run-chain':",
                    "    project = Path(args[args.index('--project') + 1])",
                    "    target = project / '.forge' / 'result.json'",
                    "    target.parent.mkdir(parents=True, exist_ok=True)",
                    "    target.write_text(json.dumps({",
                    "        'schema_version': json.loads(os.environ['FAKE_SCHEMA']),",
                    "        'run_id': 'structured-stop',",
                    "        'final_status': 'needs_continuation',",
                    "        'stop_reason_code': os.environ['FAKE_STOP_REASON'],",
                    "        'automatic_resume_allowed': json.loads(os.environ['FAKE_AUTOMATIC']),",
                    "        'final_message': 'localized human prose',",
                    "    }), encoding='utf-8')",
                    "    raise SystemExit(4)",
                    "raise SystemExit(9)",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["FAKE_STOP_REASON"] = reason
        env["FAKE_SCHEMA"] = json.dumps(schema_value)
        env["FAKE_AUTOMATIC"] = json.dumps(automatic_value)
        env["PATH"] = (
            str(root)
            + os.pathsep
            + str(Path(sys.executable).parent)
            + os.pathsep
            + env.get("PATH", "")
        )
        return subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(root / WRAPPER.name),
                "-ProjectPath",
                str(project),
                "-Goal",
                "Fake bounded task.",
                "-Mode",
                "EconomyMax",
                "-NoMonitor",
            ],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=30,
            env=env,
        )

    def test_wrapper_does_not_offer_resume_for_packet_attempt_limit(self) -> None:
        completed = self.run_fake_wrapper("packet_attempts_exhausted")
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 4, msg=output)
        self.assertIn("vycerpal jeho packet attempts", output)
        self.assertIn("Globalny chain budget tym nemusi byt vycerpany", output)
        self.assertNotIn("-ResumeRunId 'structured-stop'", output)

    def test_wrapper_offers_resume_for_chain_budget_only(self) -> None:
        completed = self.run_fake_wrapper("chain_budget_exhausted")
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 4, msg=output)
        self.assertIn("vycerpal globalny chain budget", output)
        self.assertIn("-ResumeRunId 'structured-stop'", output)

    def test_wrapper_current_result_routing_rejects_coercive_json_types(self) -> None:
        for schema_value, automatic_value in (
            ("4", False),
            (4, 0),
            (4, "false"),
        ):
            with self.subTest(
                schema_value=schema_value,
                automatic_value=automatic_value,
            ):
                completed = self.run_fake_wrapper(
                    "chain_budget_exhausted",
                    schema_value=schema_value,
                    automatic_value=automatic_value,
                )
                output = completed.stdout + completed.stderr
                self.assertEqual(completed.returncode, 4, msg=output)
                self.assertIn("neplatnymi schema/type", output)
                self.assertNotIn("-ResumeRunId 'structured-stop'", output)


if __name__ == "__main__":
    unittest.main()
