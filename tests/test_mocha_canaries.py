import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

import forge
import forge_adaptive as adaptive
from forge_reports import evaluate_test_evidence


class MochaReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.project = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def definition(**updates):
        payload = {
            "check_id": "mocha",
            "command": "npm run test",
            "check_kind": "test",
            "require_test_execution": True,
            "report_format": "mocha-text",
        }
        payload.update(updates)
        return adaptive.CheckDefinition(**payload)

    def evaluate(self, output, definition=None):
        return evaluate_test_evidence(
            self.project,
            definition or self.definition(),
            output,
            started_wall_time=time.time() - 0.2,
        )

    def test_mocha_text_success(self):
        metrics = self.evaluate("  4 passing (25ms)")
        self.assertTrue(metrics.report_valid)
        self.assertEqual((metrics.discovered, metrics.executed), (4, 4))

    def test_mocha_text_failure_blocks_gate(self):
        metrics = self.evaluate("  3 passing\n  1 failing")
        self.assertFalse(metrics.report_valid)
        self.assertEqual(metrics.failed, 1)

    def test_mocha_pending_is_counted_but_not_executed(self):
        metrics = self.evaluate("  2 passing\n  1 pending")
        self.assertTrue(metrics.report_valid)
        self.assertEqual(
            (metrics.discovered, metrics.executed, metrics.skipped), (3, 2, 1)
        )

    def test_mocha_zero_tests_is_invalid(self):
        metrics = self.evaluate("  0 passing")
        self.assertFalse(metrics.report_valid)

    def test_mocha_json_and_malformed_output(self):
        valid = self.evaluate(
            '{"stats":{"tests":3,"passes":2,"failures":0,"pending":1}}',
            self.definition(report_format="mocha-json"),
        )
        malformed = self.evaluate(
            "{not-json", self.definition(report_format="mocha-json")
        )
        self.assertTrue(valid.report_valid)
        self.assertEqual((valid.executed, valid.skipped), (2, 1))
        self.assertFalse(malformed.report_valid)
        self.assertIn("Malformed", malformed.failure_reason)


class ModelFreeCanaryTests(unittest.TestCase):
    fixtures = Path(__file__).resolve().parents[1] / "canaries"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.project = Path(self.temp.name) / "canary"
        self.project.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def evaluate_text(self, relative):
        output = (self.fixtures / relative).read_text(encoding="utf-8")
        definition = adaptive.CheckDefinition(
            check_id="pytest",
            command="python -m pytest",
            check_kind="test",
            require_test_execution=True,
            report_format="pytest-text",
        )
        return evaluate_test_evidence(
            self.project,
            definition,
            output,
            started_wall_time=time.time() - 0.2,
        )

    def copy_report(self, relative):
        source = self.fixtures / relative
        destination = self.project / source.name
        destination.write_bytes(source.read_bytes())
        return destination

    def evaluate_report(self, relative, report_format):
        destination = self.copy_report(relative)
        definition = adaptive.CheckDefinition(
            check_id=report_format,
            command="run model-free canary",
            check_kind="test",
            require_test_execution=True,
            report_path=destination.name,
            report_format=report_format,
        )
        return evaluate_test_evidence(
            self.project,
            definition,
            "",
            started_wall_time=time.time() - 0.2,
        )

    def test_python_passing_canary_has_nonzero_tests(self):
        metrics = self.evaluate_text("python/pytest-passing.txt")
        self.assertTrue(metrics.report_valid)
        self.assertEqual(metrics.executed, 3)

    def test_python_failure_canary_blocks_gate(self):
        metrics = self.evaluate_text("python/pytest-failing.txt")
        self.assertFalse(metrics.report_valid)
        self.assertEqual(metrics.failed, 1)

    def test_vitest_passing_canary(self):
        metrics = self.evaluate_report(
            "typescript/vitest-passing.json", "vitest-json"
        )
        self.assertTrue(metrics.report_valid)
        self.assertEqual(metrics.executed, 4)

    def test_vitest_failure_canary_blocks_gate(self):
        metrics = self.evaluate_report(
            "typescript/vitest-failing.json", "vitest-json"
        )
        self.assertFalse(metrics.report_valid)

    def test_vitest_zero_and_stale_canaries_block_gate(self):
        zero = self.evaluate_report(
            "typescript/vitest-zero.json", "vitest-json"
        )
        stale_path = self.copy_report("typescript/vitest-stale.json")
        old = time.time() - 120
        os.utime(stale_path, (old, old))
        definition = adaptive.CheckDefinition(
            check_id="vitest-stale",
            command="run model-free stale canary",
            check_kind="test",
            require_test_execution=True,
            report_path=stale_path.name,
            report_format="vitest-json",
        )
        stale = evaluate_test_evidence(
            self.project,
            definition,
            "",
            started_wall_time=time.time(),
        )
        self.assertFalse(zero.report_valid)
        self.assertIn("zero tests", zero.failure_reason)
        self.assertFalse(stale.report_valid)
        self.assertIn("stale", stale.failure_reason)

    def test_playwright_main_flow_canary(self):
        passing = self.evaluate_report(
            "playwright/main-flow-passing.json", "playwright-json"
        )
        failing = self.evaluate_report(
            "playwright/main-flow-failing.json", "playwright-json"
        )
        self.assertTrue(passing.report_valid)
        self.assertFalse(failing.report_valid)

    def test_playwright_skipped_and_flaky_canaries(self):
        skipped = self.evaluate_report(
            "playwright/main-flow-skipped.json", "playwright-json"
        )
        flaky = self.evaluate_report(
            "playwright/main-flow-flaky.json", "playwright-json"
        )
        self.assertTrue(skipped.report_valid)
        self.assertEqual(
            (skipped.discovered, skipped.executed, skipped.skipped),
            (3, 1, 2),
        )
        self.assertTrue(flaky.report_valid)
        self.assertEqual(
            (flaky.discovered, flaky.executed, flaky.passed),
            (2, 2, 2),
        )

    def test_android_multimodule_canary_passes_release_gate(self):
        source = self.fixtures / "android"
        shutil.copytree(source, self.project / "android")
        for path in (self.project / "android").rglob("TEST-*.xml"):
            path.touch()
        definition = adaptive.CheckDefinition(
            check_id="android-unit",
            command=r".\gradlew.bat testDebugUnitTest",
            tier="release",
            required_before_done=True,
            check_kind="test",
            require_test_execution=True,
            report_path="android",
            report_glob="**/build/test-results/testDebugUnitTest/TEST-*.xml",
            report_format="gradle-junit",
        )
        metrics = evaluate_test_evidence(
            self.project,
            definition,
            "",
            started_wall_time=time.time() - 0.2,
        )
        result = forge.CheckResult(
            command=definition.command,
            check_id=definition.check_id,
            tier="release",
            exit_code=0,
            output="model-free Android canary",
            tests_discovered=metrics.discovered,
            tests_executed=metrics.executed,
            report_valid=metrics.report_valid,
        )
        self.assertEqual(
            (metrics.discovered, metrics.executed, metrics.report_file_count),
            (5, 4, 2),
        )
        self.assertTrue(forge.release_checks_passed([result]))

    def test_android_instrumentation_canary_is_documented_as_manual(self):
        text = (self.fixtures / "README.md").read_text(encoding="utf-8")
        self.assertIn("instrumentation remains a manual canary", text)


if __name__ == "__main__":
    unittest.main()
