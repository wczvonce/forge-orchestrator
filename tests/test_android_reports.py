import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import forge
import forge_adaptive as adaptive
from forge_reports import evaluate_test_evidence


class AndroidReportAggregationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.project = Path(self.temp.name) / "android-project"
        self.project.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def junit(tests=1, failures=0, errors=0, skipped=0):
        return (
            f'<testsuite tests="{tests}" failures="{failures}" '
            f'errors="{errors}" skipped="{skipped}"/>'
        )

    def write_report(self, module, relative_dir, name, content=None):
        report = self.project / module / relative_dir / name
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(
            content if content is not None else self.junit(), encoding="utf-8"
        )
        return report

    def definition(self, **overrides):
        payload = {
            "check_id": "android-unit",
            "command": r".\gradlew.bat --no-daemon testDebugUnitTest",
            "tier": "release",
            "required_before_done": True,
            "check_kind": "test",
            "require_test_execution": True,
            "report_path": ".",
            "report_glob": "**/build/test-results/testDebugUnitTest/TEST-*.xml",
            "report_format": "gradle-junit",
        }
        payload.update(overrides)
        return adaptive.CheckDefinition(**payload)

    def evaluate(self, definition=None, *, started=None):
        return evaluate_test_evidence(
            self.project,
            definition or self.definition(),
            "",
            started_wall_time=started or time.time() - 0.2,
        )

    def test_multimodule_reports_are_aggregated(self):
        self.write_report(
            "app",
            "build/test-results/testDebugUnitTest",
            "TEST-app.xml",
            self.junit(tests=3, skipped=1),
        )
        self.write_report(
            "feature",
            "build/test-results/testDebugUnitTest",
            "TEST-feature.xml",
            self.junit(tests=4, failures=1),
        )

        metrics = self.evaluate()

        self.assertEqual(metrics.report_file_count, 2)
        self.assertEqual(
            (
                metrics.discovered,
                metrics.executed,
                metrics.passed,
                metrics.failed,
                metrics.skipped,
            ),
            (7, 6, 5, 1, 1),
        )
        self.assertFalse(metrics.report_valid)

    def test_dynamic_module_name_does_not_require_app_module(self):
        self.write_report(
            "tenant-ledger",
            "build/test-results/testDebugUnitTest",
            "TEST-ledger.xml",
            self.junit(tests=2),
        )
        metrics = self.evaluate()
        self.assertTrue(metrics.report_valid)
        self.assertIn("tenant-ledger", metrics.report_files[0])

    def test_empty_report_directory_is_invalid(self):
        (self.project / "empty").mkdir()
        metrics = self.evaluate(
            self.definition(report_path="empty", report_glob="TEST-*.xml")
        )
        self.assertFalse(metrics.report_valid)
        self.assertIn("matched", metrics.failure_reason)

    def test_missing_report_directory_is_invalid(self):
        metrics = self.evaluate(
            self.definition(report_path="missing", report_glob="TEST-*.xml")
        )
        self.assertFalse(metrics.report_valid)
        self.assertIn("does not exist", metrics.failure_reason)

    def test_zero_test_aggregate_is_invalid(self):
        self.write_report(
            "app",
            "build/test-results/testDebugUnitTest",
            "TEST-zero.xml",
            self.junit(tests=0),
        )
        metrics = self.evaluate()
        self.assertFalse(metrics.report_valid)
        self.assertIn("zero tests", metrics.failure_reason)

    def test_failed_test_in_any_module_invalidates_aggregate(self):
        self.write_report(
            "app",
            "build/test-results/testDebugUnitTest",
            "TEST-green.xml",
            self.junit(tests=2),
        )
        self.write_report(
            "feature",
            "build/test-results/testDebugUnitTest",
            "TEST-red.xml",
            self.junit(tests=1, errors=1),
        )
        metrics = self.evaluate()
        self.assertFalse(metrics.report_valid)
        self.assertEqual(metrics.failed, 1)

    def test_malformed_report_invalidates_entire_aggregate(self):
        self.write_report(
            "app",
            "build/test-results/testDebugUnitTest",
            "TEST-green.xml",
            self.junit(tests=2),
        )
        self.write_report(
            "feature",
            "build/test-results/testDebugUnitTest",
            "TEST-bad.xml",
            "<testsuite",
        )
        metrics = self.evaluate()
        self.assertFalse(metrics.report_valid)
        self.assertIn("Invalid test report", metrics.failure_reason)

    def test_stale_reports_are_not_counted_when_fresh_reports_exist(self):
        stale = self.write_report(
            "old",
            "build/test-results/testDebugUnitTest",
            "TEST-old.xml",
            self.junit(tests=20),
        )
        old_time = time.time() - 120
        os.utime(stale, (old_time, old_time))
        self.write_report(
            "fresh",
            "build/test-results/testDebugUnitTest",
            "TEST-fresh.xml",
            self.junit(tests=2),
        )
        metrics = self.evaluate(started=time.time())
        self.assertTrue(metrics.report_valid)
        self.assertEqual((metrics.discovered, metrics.report_file_count), (2, 1))

    def test_all_stale_reports_are_invalid(self):
        stale = self.write_report(
            "old",
            "build/test-results/testDebugUnitTest",
            "TEST-old.xml",
            self.junit(tests=2),
        )
        old_time = time.time() - 120
        os.utime(stale, (old_time, old_time))
        metrics = self.evaluate(started=time.time())
        self.assertFalse(metrics.report_valid)
        self.assertIn("stale", metrics.failure_reason)

    def test_report_glob_path_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            self.definition(report_glob="../**/TEST-*.xml")

    def test_symlink_escape_is_rejected_when_supported(self):
        outside = self.project.parent / "outside-reports"
        outside.mkdir()
        (outside / "TEST-secret.xml").write_text(
            self.junit(tests=1), encoding="utf-8"
        )
        link = self.project / "linked"
        try:
            os.symlink(outside, link, target_is_directory=True)
        except OSError as exc:
            if os.name != "nt":
                self.skipTest(f"Directory symlinks are unavailable: {exc}")
            junction = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(outside)],
                text=True,
                capture_output=True,
                errors="replace",
            )
            if junction.returncode != 0:
                self.skipTest(
                    "Directory links are unavailable: "
                    f"{exc}; junction: {junction.stderr or junction.stdout}"
                )
        metrics = self.evaluate(
            self.definition(report_path=".", report_glob="linked/TEST-*.xml")
        )
        self.assertFalse(metrics.report_valid)
        self.assertIn("Unsafe", metrics.failure_reason)

    def test_android_instrumentation_report_glob_is_aggregated(self):
        self.write_report(
            "mobile",
            "build/outputs/androidTest-results/connected/pixel_api_35",
            "TEST-device.xml",
            self.junit(tests=3, skipped=1),
        )
        metrics = self.evaluate(
            self.definition(
                check_id="android-e2e",
                command=r".\gradlew.bat --no-daemon connectedDebugAndroidTest",
                report_glob=(
                    "**/build/outputs/androidTest-results/connected/**/TEST-*.xml"
                ),
                report_format="android-junit",
            )
        )
        self.assertTrue(metrics.report_valid)
        self.assertEqual((metrics.discovered, metrics.executed), (3, 2))

    def test_lint_and_build_do_not_require_test_counts(self):
        for kind in ("lint", "build"):
            definition = adaptive.CheckDefinition(
                check_id=f"android-{kind}",
                command=f"fake {kind}",
                check_kind=kind,
            )
            metrics = self.evaluate(definition)
            self.assertTrue(metrics.report_valid)
            self.assertIsNone(metrics.executed)

    def test_real_fake_gradle_process_produces_fresh_release_evidence(self):
        script = self.project / "fake_gradle.py"
        script.write_text(
            "from pathlib import Path\n"
            "p = Path('feature/build/test-results/testDebugUnitTest')\n"
            "p.mkdir(parents=True, exist_ok=True)\n"
            "(p / 'TEST-fake.xml').write_text("
            "'<testsuite tests=\"3\" failures=\"0\" skipped=\"1\"/>', "
            "encoding='utf-8')\n"
            "print('fake Gradle completed')\n",
            encoding="utf-8",
        )
        command = f'"{sys.executable}" "{script.name}"'
        config = {
            **forge.DEFAULT_CONFIG,
            "adaptive_orchestration": True,
            "sandbox_checks": "off",
            "check_definitions": [
                {
                    **self.definition().model_dump(),
                    "command": command,
                },
                {
                    "check_id": "android-release-build",
                    "command": f'"{sys.executable}" -c "print(\'release build ok\')"',
                    "tier": "release",
                    "required_before_done": True,
                    "check_kind": "build",
                },
            ],
        }

        results = forge.run_checks(self.project, config, tier="release")

        self.assertEqual(len(results), 2)
        self.assertTrue(forge.release_checks_passed(results))
        unit = next(item for item in results if item.check_id == "android-unit")
        self.assertEqual(
            (unit.tests_discovered, unit.tests_executed, unit.report_file_count),
            (3, 2, 1),
        )

    def test_android_config_wires_dynamic_test_reports_and_non_test_kinds(self):
        config_path = Path(__file__).resolve().parents[1] / "forge.android.config.json"
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        definitions = {
            item.check_id: item
            for item in adaptive.normalize_check_definitions(payload)
        }
        self.assertEqual(definitions["android-lint"].check_kind, "lint")
        self.assertEqual(definitions["android-compile"].check_kind, "build")
        self.assertEqual(definitions["android-release-build"].check_kind, "build")
        self.assertEqual(definitions["android-unit"].report_path, ".")
        self.assertIn("**/build/test-results/", definitions["android-unit"].report_glob)
        self.assertTrue(definitions["android-unit"].require_test_execution)
        self.assertIn(
            "**/build/outputs/androidTest-results/",
            definitions["android-e2e"].report_glob,
        )
        self.assertTrue(definitions["android-e2e"].require_test_execution)


if __name__ == "__main__":
    unittest.main()
