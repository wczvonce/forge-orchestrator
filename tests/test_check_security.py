import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import forge


class CheckSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.project = Path(self.temp.name) / "project"
        self.project.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def config(self, command):
        return {
            **forge.DEFAULT_CONFIG,
            "adaptive_orchestration": True,
            "sandbox_checks": "off",
            "check_definitions": [
                {
                    "check_id": "safe-build",
                    "command": command,
                    "tier": "release",
                    "required_before_done": True,
                    "check_kind": "build",
                }
            ],
        }

    def write_script(self, source):
        path = self.project / "check_script.py"
        path.write_text(source, encoding="utf-8")
        return f'"{sys.executable}" "{path.name}"'

    def test_check_environment_scrubs_ssh_and_disables_git_credentials(self):
        poisoned = {
            "SSH_AUTH_SOCK": "agent",
            "SSH_AGENT_PID": "123",
            "GIT_ASKPASS": "askpass",
            "SSH_ASKPASS": "ssh-askpass",
            "GIT_SSH_COMMAND": "ssh -i secret",
            "OPENAI_API_KEY": "secret",
        }
        with mock.patch.dict(os.environ, poisoned, clear=False):
            env = forge.build_check_environment(self.project)
        for key in poisoned:
            self.assertNotIn(key, env)
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(env["GCM_INTERACTIVE"], "Never")
        global_config = Path(env["GIT_CONFIG_GLOBAL"])
        self.assertTrue(global_config.is_file())
        self.assertEqual(global_config.read_text(encoding="utf-8"), "")
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "core.hooksPath")
        self.assertTrue(Path(env["GIT_CONFIG_VALUE_0"]).is_dir())

    def test_ordinary_safe_check_passes(self):
        command = self.write_script("print('safe build')\n")
        results = forge.run_checks(
            self.project, self.config(command), tier="release"
        )
        self.assertTrue(forge.checks_passed(results))

    def test_check_created_git_hook_is_detected(self):
        git_dir = self.project / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("[core]\n", encoding="utf-8")
        baseline = forge.git_metadata_manifest(self.project)
        command = self.write_script(
            "from pathlib import Path\n"
            "p = Path('.git/hooks/pre-commit')\n"
            "p.parent.mkdir(parents=True, exist_ok=True)\n"
            "p.write_text('malicious hook', encoding='utf-8')\n"
        )
        results = forge.run_checks(
            self.project,
            self.config(command),
            tier="release",
            git_metadata_baseline=baseline,
        )
        self.assertFalse(forge.checks_passed(results))
        self.assertIn(".git/hooks/pre-commit", results[0].report_failure_reason)

    def test_check_changed_git_config_is_detected(self):
        git_dir = self.project / ".git"
        git_dir.mkdir()
        config_path = git_dir / "config"
        config_path.write_text("[core]\n", encoding="utf-8")
        baseline = forge.git_metadata_manifest(self.project)
        command = self.write_script(
            "from pathlib import Path\n"
            "p = Path('.git/config')\n"
            "p.write_text(p.read_text() + '[credential]\\nhelper=store\\n')\n"
        )
        results = forge.run_checks(
            self.project,
            self.config(command),
            tier="release",
            git_metadata_baseline=baseline,
        )
        self.assertFalse(forge.checks_passed(results))
        self.assertIn(".git/config", results[0].report_failure_reason)

    def test_manual_auto_mode_emits_explicit_unsandboxed_warning(self):
        command = self.write_script("print('manual check')\n")
        config = self.config(command)
        config["sandbox_checks"] = "auto"
        output = io.StringIO()
        with mock.patch.object(forge.shutil, "which", return_value=None):
            with contextlib.redirect_stdout(output):
                results = forge.run_checks(self.project, config, tier="release")
        self.assertTrue(forge.checks_passed(results))
        self.assertIn("BEZPEČNOSTNÉ VAROVANIE", output.getvalue())
        self.assertIn("bez OS sandboxu", output.getvalue())

    def test_strict_mode_without_sandbox_fails(self):
        with mock.patch.object(forge.shutil, "which", return_value=None):
            with self.assertRaises(SystemExit):
                forge.check_command_args(
                    "python -m unittest",
                    self.project,
                    {"sandbox_checks": "required"},
                )

    def test_internal_git_commands_disable_hooks_and_prompts(self):
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(forge, "run_process", return_value=completed) as run:
            code, _ = forge.run_git(self.project, "status", "--short")
        self.assertEqual(code, 0)
        args = run.call_args.args[0]
        self.assertEqual(args[:2], ["git", "-c"])
        self.assertTrue(args[2].startswith("core.hooksPath="))
        env = run.call_args.kwargs["env"]
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(env["GCM_INTERACTIVE"], "Never")

    def test_subscription_environment_still_keeps_non_secret_transport(self):
        with mock.patch.dict(
            os.environ,
            {"PATH": "transport-path", "ANTHROPIC_API_KEY": "secret"},
            clear=False,
        ):
            env = forge.subscription_only_env()
        self.assertEqual(env["PATH"], "transport-path")
        self.assertNotIn("ANTHROPIC_API_KEY", env)

    def test_runtime_temp_directory_is_private_and_socket_capable_on_wsl(self):
        runtime_dir = forge.project_runtime_temp_dir(self.project, "checks")
        self.assertTrue(runtime_dir.is_dir())
        if forge.running_in_wsl():
            self.assertTrue(str(runtime_dir).startswith("/tmp/gpt-claude-forge/"))
            self.assertFalse(str(runtime_dir).startswith("/mnt/"))
            self.assertEqual(runtime_dir.stat().st_mode & 0o777, 0o700)

    def test_claude_wsl_environment_uses_native_runtime_paths(self):
        env = forge.claude_subprocess_env(self.project)
        if forge.running_in_wsl():
            self.assertTrue(env["TMPDIR"].startswith("/tmp/gpt-claude-forge/"))

    def test_outer_claude_srt_policy_limits_secrets_and_writes(self):
        config = {**forge.DEFAULT_CONFIG, "security_profile": "strict"}
        with mock.patch.object(forge, "running_in_wsl", return_value=True):
            with mock.patch.object(forge.shutil, "which", return_value="/usr/local/bin/srt"):
                self.assertTrue(forge.use_outer_claude_srt(config))
                path = forge.build_claude_srt_settings(self.project, config)
        payload = json.loads(path.read_text(encoding="utf-8"))
        filesystem = payload["filesystem"]
        self.assertIn("/mnt/c/Users", filesystem["denyRead"])
        self.assertIn(".", filesystem["allowWrite"])
        self.assertIn(".git/config", filesystem["denyWrite"])
        self.assertTrue(payload["network"]["strictAllowlist"])
        self.assertEqual(payload["network"]["tlsTerminate"], {})
        credential = payload["credentials"]["files"][0]
        self.assertEqual(
            credential["path"],
            str(Path.home().resolve() / ".claude" / ".credentials.json"),
        )
        self.assertIn(credential["path"], filesystem["allowRead"])
        self.assertIn(credential["path"], filesystem["denyWrite"])
        self.assertEqual(credential["mode"], "mask")
        self.assertEqual(credential["onExtractNoMatch"], "error")
        self.assertIn("api.anthropic.com", credential["injectHosts"])


if __name__ == "__main__":
    unittest.main()
