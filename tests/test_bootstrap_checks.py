import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import forge
from forge_adaptive import CheckContract


class BootstrapCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.project = Path(self.temp.name) / "project"
        self.project.mkdir()
        forge.ensure_git_repo(self.project)
        self.config = {
            **forge.DEFAULT_CONFIG,
            "adaptive_orchestration": True,
            "sandbox_checks": "off",
            "check_definitions": [],
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_auto_discovery_has_real_unborn_repository_checks(self):
        definitions = forge.discover_check_definitions(
            self.project, self.config, "smoke"
        )
        commands = [item.command for item in definitions]
        self.assertEqual(
            commands[:3],
            [
                forge.FORGE_BOOTSTRAP_CHECK_COMMAND,
                "git diff --check",
                "git diff --cached --check",
            ],
        )
        self.assertTrue(all(item.required_before_done for item in definitions))
        self.assertEqual(definitions[0].check_kind, "security")
        self.assertEqual(
            [item.check_id for item in definitions[:3]],
            [
                "auto-bootstrap-integrity",
                "auto-git-worktree-whitespace",
                "auto-git-index-whitespace",
            ],
        )

    def test_untracked_clean_text_is_actually_inspected(self):
        (self.project / "main.py").write_text(
            "print('bootstrap works')\n", encoding="utf-8"
        )
        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 0, output)
        self.assertIn("1 pending text files inspected", output)

    def test_untracked_trailing_whitespace_fails_but_markdown_hard_break_passes(self):
        readme = self.project / "README.md"
        readme.write_text("legitimate hard break  \n", encoding="utf-8")
        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 0, output)

        (self.project / "main.py").write_text(
            "print('bad') \n", encoding="utf-8"
        )
        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 1)
        self.assertIn("trailing-whitespace", output)
        self.assertIn('"main.py":1', output)

    def test_secret_finding_never_echoes_the_secret_value(self):
        # Build credential-shaped fixtures at runtime so Forge's own repository
        # bootstrap scan does not correctly reject this test source.
        secret = "".join(("AK", "IA1234567890", "ABCDEF"))
        documented_example = "".join(("AK", "IAIOSFODNN7", "EXAMPLE"))
        (self.project / "config.py").write_text(
            f'AWS_ACCESS_KEY = "{secret}"\n', encoding="utf-8"
        )
        (self.project / "example.py").write_text(
            f'AWS_ACCESS_KEY = "{documented_example}"\n',
            encoding="utf-8",
        )
        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 1)
        self.assertIn("aws-access-key", output)
        self.assertNotIn(secret, output)
        self.assertNotIn(documented_example, output)

    def test_json_password_assignment_is_detected_without_echo(self):
        secret = "JsonPassword-9f8e7d6c5b4a"
        (self.project / "config.json").write_text(
            json.dumps({"password": secret}),
            encoding="utf-8",
        )
        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 1)
        self.assertIn("credential-assignment", output)
        self.assertNotIn(secret, output)

    def test_literal_conflict_fixture_is_not_a_false_positive(self):
        fixture = self.project / "tests" / "fixtures" / "merge.txt"
        fixture.parent.mkdir(parents=True)
        fixture.write_text(
            "<<<<<<< HEAD\nleft\n=======\nright\n>>>>>>> branch\n",
            encoding="utf-8",
        )
        (self.project / "README.md").write_text(
            "Ordinary document separator\n=======\n",
            encoding="utf-8",
        )
        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 0, output)

        source = self.project / "merge.txt"
        source.write_text(
            "<<<<<<< HEAD\nleft\n=======\nright\n>>>>>>> branch\n",
            encoding="utf-8",
        )
        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 1)
        self.assertIn("merge-conflict-marker", output)

    def test_staged_whitespace_is_covered_by_cached_diff_check(self):
        (self.project / "staged.py").write_text("value = 1 \n", encoding="utf-8")
        code, output = forge.run_git(self.project, "add", "--", "staged.py")
        self.assertEqual(code, 0, output)
        results = forge.run_checks(
            self.project, self.config, tier="smoke"
        )
        cached = [
            item for item in results if item.command == "git diff --cached --check"
        ]
        self.assertEqual(len(cached), 1)
        self.assertNotEqual(cached[0].exit_code, 0)
        self.assertFalse(forge.checks_passed(results))

    def test_staged_secret_is_scanned_after_worktree_is_cleaned(self):
        secret = "".join(("AK", "IA1234567890", "ABCDEF"))
        path = self.project / "config.py"
        path.write_text(
            f'AWS_ACCESS_KEY = "{secret}"\n', encoding="utf-8"
        )
        code, output = forge.run_git(self.project, "add", "--", "config.py")
        self.assertEqual(code, 0, output)
        path.write_text("AWS_ACCESS_KEY = None\n", encoding="utf-8")

        exit_code, scan_output = forge.run_bootstrap_integrity_check(
            self.project
        )
        self.assertEqual(exit_code, 1)
        self.assertIn("staged-index-aws-access-key", scan_output)
        self.assertIn('"config.py":1', scan_output)
        self.assertNotIn(secret, scan_output)

    def test_symlink_targets_are_validated_without_external_dereference(self):
        target = self.project / "target.txt"
        target.write_text("safe\n", encoding="utf-8")
        code, output = forge.run_git(
            self.project, "add", "--", "target.txt"
        )
        self.assertEqual(code, 0, output)
        index_entries, error = forge._git_staged_entries(self.project)
        self.assertIsNone(error)
        index_symlink_targets, error = forge._git_index_symlink_targets(
            self.project, index_entries
        )
        self.assertIsNone(error)
        # The helper's production callers construct candidates from the
        # canonical project root. Match that contract here as well: GitHub's
        # Windows workspace may otherwise spell the same directory through a
        # path alias that Path.relative_to correctly treats as a different
        # lexical root.
        link = self.project.resolve() / "link.txt"
        self.assertIsNone(
            forge._bootstrap_symlink_finding(
                self.project.resolve(),
                link,
                "target.txt",
                index_entries=index_entries,
                index_symlink_targets=index_symlink_targets,
            )
        )
        self.assertEqual(
            forge._bootstrap_symlink_finding(
                self.project.resolve(),
                link,
                "../outside.txt",
                index_entries=index_entries,
                index_symlink_targets=index_symlink_targets,
            ),
            "symlink-outside-project-target",
        )
        self.assertEqual(
            forge._bootstrap_symlink_finding(
                self.project.resolve(),
                link,
                str(target.resolve()),
                index_entries=index_entries,
                index_symlink_targets=index_symlink_targets,
            ),
            "symlink-absolute-target",
        )
        self.assertEqual(
            forge._bootstrap_symlink_finding(
                self.project.resolve(),
                link,
                "missing.txt",
                index_entries=index_entries,
                index_symlink_targets=index_symlink_targets,
            ),
            "symlink-dangling-target",
        )

    def test_staged_internal_symlink_passes_but_escape_fails(self):
        target = self.project / "target.txt"
        target.write_text("safe\n", encoding="utf-8")
        code, output = forge.run_git(
            self.project, "add", "--", "target.txt"
        )
        self.assertEqual(code, 0, output)

        def stage_link(target_text):
            code, payload, error = forge._git_bytes(
                self.project,
                "hash-object",
                "-w",
                "--stdin",
                input_bytes=target_text.encode("utf-8"),
            )
            self.assertEqual(code, 0, error)
            object_id = payload.decode("ascii").strip()
            code, output = forge.run_git(
                self.project,
                "update-index",
                "--add",
                "--cacheinfo",
                f"120000,{object_id},link.txt",
            )
            self.assertEqual(code, 0, output)

        stage_link("target.txt")
        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 0, output)

        stage_link("../outside.txt")
        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 1)
        self.assertIn(
            "staged-index-symlink-outside-project-target", output
        )

    def test_staged_symlink_to_ignored_secret_is_rejected(self):
        (self.project / ".gitignore").write_text(
            ".env\n", encoding="utf-8"
        )
        secret_line = "".join(
            ("API_", "KEY=", "RealSecret-", "1234567890-", "ABCDE", "\n")
        )
        (self.project / ".env").write_text(secret_line, encoding="utf-8")
        code, payload, error = forge._git_bytes(
            self.project,
            "hash-object",
            "-w",
            "--stdin",
            input_bytes=b".env",
        )
        self.assertEqual(code, 0, error)
        object_id = payload.decode("ascii").strip()
        code, output = forge.run_git(
            self.project,
            "update-index",
            "--add",
            "--cacheinfo",
            f"120000,{object_id},public-config",
        )
        self.assertEqual(code, 0, output)

        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 1)
        self.assertIn(
            "staged-index-symlink-untracked-target", output
        )
        self.assertNotIn(secret_line.strip().split("=", 1)[1], output)

    def test_staged_symlink_chain_is_validated_through_index(self):
        target = self.project / "target.txt"
        target.write_text("safe\n", encoding="utf-8")
        code, output = forge.run_git(
            self.project, "add", "--", "target.txt"
        )
        self.assertEqual(code, 0, output)

        def stage_link(path, target_text):
            code, payload, error = forge._git_bytes(
                self.project,
                "hash-object",
                "-w",
                "--stdin",
                input_bytes=target_text.encode("utf-8"),
            )
            self.assertEqual(code, 0, error)
            object_id = payload.decode("ascii").strip()
            code, output = forge.run_git(
                self.project,
                "update-index",
                "--add",
                "--cacheinfo",
                f"120000,{object_id},{path}",
            )
            self.assertEqual(code, 0, output)

        stage_link("link-two", "target.txt")
        stage_link("link-one", "link-two")
        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 0, output)

        secret_line = "".join(
            ("API_", "KEY=", "RealSecret-", "1234567890-", "ABCDE", "\n")
        )
        (self.project / ".env").write_text(secret_line, encoding="utf-8")
        (self.project / ".gitignore").write_text(
            ".env\n", encoding="utf-8"
        )
        stage_link("link-two", ".env")
        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 1)
        self.assertIn("symlink-untracked-target", output)

        stage_link("link-two", "link-one")
        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 1)
        self.assertIn("symlink-cycle", output)

    def test_non_utf8_git_paths_fail_closed_before_keying(self):
        with patch.object(
            forge,
            "_git_bytes",
            return_value=(0, b"safe\0bad\xff\0", None),
        ):
            paths, error = forge._git_nul_paths(
                self.project, "diff", "--name-only", "-z"
            )
        self.assertEqual(paths, set())
        self.assertIn("non-UTF-8 path", error)

        staged_payload = (
            b"100644 "
            + (b"0" * 40)
            + b" 0\tbad\xff\0"
        )
        with patch.object(
            forge,
            "_git_bytes",
            return_value=(0, staged_payload, None),
        ):
            entries, error = forge._git_staged_entries(self.project)
        self.assertEqual(entries, {})
        self.assertIn("non-UTF-8 path", error)

    def test_new_gitlink_is_fail_closed(self):
        code, tree_payload, error = forge._git_bytes(
            self.project, "mktree", input_bytes=b""
        )
        self.assertEqual(code, 0, error)
        tree_id = tree_payload.decode("ascii").strip()
        commit_payload = (
            f"tree {tree_id}\n"
            "author Forge Test <forge@example.invalid> 0 +0000\n"
            "committer Forge Test <forge@example.invalid> 0 +0000\n"
            "\nfixture commit\n"
        ).encode("utf-8")
        code, commit_output, error = forge._git_bytes(
            self.project,
            "hash-object",
            "-t",
            "commit",
            "-w",
            "--stdin",
            input_bytes=commit_payload,
        )
        self.assertEqual(code, 0, error)
        commit_id = commit_output.decode("ascii").strip()
        code, output = forge.run_git(
            self.project,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{commit_id},vendor/module",
        )
        self.assertEqual(code, 0, output)
        exit_code, output = forge.run_bootstrap_integrity_check(self.project)
        self.assertEqual(exit_code, 1)
        self.assertIn("staged-index-gitlink-not-allowed", output)

    def test_package_runner_emergence_requires_review_then_relocks(self):
        original = forge.ensure_check_contract(self.project, self.config)
        (self.project / "package.json").write_text(
            json.dumps({"scripts": {"test": "node --test"}}),
            encoding="utf-8",
        )
        drift = forge.check_contract_runtime_error(
            self.project, original, self.config
        )
        self.assertIn("Auto-discovered check runners drifted", drift)
        not_yet_approved = forge.ensure_check_contract(
            self.project, self.config
        )
        self.assertEqual(
            not_yet_approved.contract_hash,
            original.contract_hash,
        )
        evidence = forge.check_contract_drift_evidence(
            self.project, original, self.config
        )
        self.assertEqual(
            evidence["definition_changes"]["added"][0]["check_id"],
            "auto-npm-test",
        )
        prompt = forge.build_review_prompt(
            "Build app",
            2,
            "(evidence)",
            None,
            [],
            0,
            self.config,
            check_contract_evidence=evidence,
        )
        self.assertIn("CHECK-CONTRACT SEMANTIC DIFF", prompt)
        self.assertIn(evidence["current_semantic_hash"], prompt)
        self.assertIn(evidence["proposed_semantic_hash"], prompt)
        ordinary = forge.Decision(
            status="continue",
            assessment="Continue without approving contract drift.",
            next_prompt="Implement the packet.",
        )
        unchanged, approved = forge.apply_check_contract_approval(
            self.project,
            self.config,
            original,
            ordinary,
            evidence,
        )
        self.assertFalse(approved)
        self.assertEqual(unchanged.contract_hash, original.contract_hash)

        approval = forge.Decision(
            status="continue",
            assessment="Runner addition preserves all mandatory checks.",
            next_prompt="Implement the packet.",
            approve_check_contract_drift=True,
            check_contract_approval_reason=(
                "Compared every semantic field and indirect hash; the npm test "
                "runner is additive and no required gate is weakened."
            ),
        )
        updated, approved = forge.apply_check_contract_approval(
            self.project,
            self.config,
            original,
            approval,
            evidence,
        )
        self.assertTrue(approved)
        self.assertNotEqual(original.contract_hash, updated.contract_hash)
        self.assertIn(
            "npm run test",
            [item.command for item in updated.check_definitions],
        )
        stored = CheckContract.model_validate_json(
            (self.project / ".forge" / "check-contract.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(stored.contract_hash, updated.contract_hash)
        self.assertIsNone(
            forge.check_contract_runtime_error(
                self.project, updated, self.config
            )
        )

    def test_new_runner_is_not_executed_before_contract_review(self):
        original = forge.ensure_check_contract(self.project, self.config)
        (self.project / "package.json").write_text(
            json.dumps(
                {
                    "scripts": {
                        "test": (
                            "node -e \"require('fs').writeFileSync("
                            "'runner-executed.txt','yes')\""
                        )
                    }
                }
            ),
            encoding="utf-8",
        )
        results = forge.run_checks(
            self.project,
            self.config,
            tier="release",
            check_contract=original,
        )
        self.assertFalse((self.project / "runner-executed.txt").exists())
        self.assertNotIn(
            "npm run test",
            [item.command for item in results],
        )
        self.assertFalse(forge.checks_passed(results))
        self.assertTrue(
            all(not item.check_contract_valid for item in results)
        )
        self.assertTrue(
            all(
                "Auto-discovered check runners drifted"
                in (item.report_failure_reason or "")
                for item in results
            )
        )

    def test_auto_runner_ids_do_not_shift_when_a_runner_appears(self):
        before = forge.discover_check_definitions(
            self.project, self.config, "release"
        )
        before_by_command = {
            item.command: item.check_id for item in before
        }
        (self.project / "package.json").write_text(
            json.dumps({"scripts": {"test": "node --test"}}),
            encoding="utf-8",
        )
        after = forge.discover_check_definitions(
            self.project, self.config, "release"
        )
        after_by_command = {item.command: item.check_id for item in after}
        for command, check_id in before_by_command.items():
            self.assertEqual(after_by_command[command], check_id)
        self.assertEqual(after_by_command["npm run test"], "auto-npm-test")

    def test_colliding_auto_runner_ids_are_disambiguated_deterministically(self):
        commands = ["npm run test", "npm run test -- --coverage"]
        with patch.object(forge, "discover_checks", return_value=commands):
            first = forge.discover_check_definitions(
                self.project, self.config, "release"
            )
            second = forge.discover_check_definitions(
                self.project, self.config, "release"
            )
        first_by_command = {
            item.command: item.check_id for item in first
        }
        second_by_command = {
            item.command: item.check_id for item in second
        }
        self.assertEqual(first_by_command, second_by_command)
        self.assertEqual(first_by_command["npm run test"], "auto-npm-test")
        self.assertRegex(
            first_by_command["npm run test -- --coverage"],
            r"^auto-npm-test-[a-f0-9]{12}$",
        )
        self.assertEqual(
            len(first_by_command.values()),
            len(set(first_by_command.values())),
        )

    def test_gradle_wrapper_emergence_is_auto_discovered_and_relocked(self):
        original = forge.ensure_check_contract(self.project, self.config)
        (self.project / "build.gradle.kts").write_text(
            "plugins { java }\n", encoding="utf-8"
        )
        wrapper_name = "gradlew.bat" if os.name == "nt" else "gradlew"
        (self.project / wrapper_name).write_text(
            "@echo off\n" if os.name == "nt" else "#!/bin/sh\n",
            encoding="utf-8",
        )
        drift = forge.check_contract_runtime_error(
            self.project, original, self.config
        )
        self.assertIn("Auto-discovered check runners drifted", drift)

        updated = forge.ensure_check_contract(
            self.project,
            self.config,
            approve_indirect_drift=True,
            change_reason="Codex reviewed the newly discovered Gradle wrapper.",
        )
        self.assertNotEqual(original.contract_hash, updated.contract_hash)
        self.assertTrue(
            any(
                "gradlew" in item.command and " test" in item.command
                for item in updated.check_definitions
            )
        )
        gradle_check = next(
            item
            for item in updated.check_definitions
            if "gradlew" in item.command and " test" in item.command
        )
        self.assertTrue(gradle_check.require_test_execution)
        self.assertEqual(gradle_check.report_format, "gradle-junit")
        self.assertEqual(
            gradle_check.report_glob,
            "**/build/test-results/**/*.xml",
        )


if __name__ == "__main__":
    unittest.main()
