from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class TestMetrics(BaseModel):
    discovered: int | None = None
    executed: int | None = None
    passed: int | None = None
    failed: int | None = None
    skipped: int | None = None
    report_path: str | None = None
    report_format: str | None = None
    report_valid: bool = True
    failure_reason: str | None = None


def _integer(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _text_metrics(text: str) -> TestMetrics:
    unittest_match = re.search(r"\bRan\s+(\d+)\s+tests?\b", text, re.I)
    if unittest_match:
        executed = _integer(unittest_match.group(1))
        failures = sum(
            _integer(value)
            for value in re.findall(r"\b(?:failures|errors)=(\d+)", text, re.I)
        )
        skipped_match = re.search(r"\bskipped=(\d+)", text, re.I)
        skipped = _integer(skipped_match.group(1)) if skipped_match else 0
        passed = max(0, executed - failures - skipped)
        return TestMetrics(
            discovered=executed,
            executed=max(0, executed - skipped),
            passed=passed,
            failed=failures,
            skipped=skipped,
            report_format="unittest-text",
        )

    collected = re.search(r"\bcollected\s+(\d+)\s+items?\b", text, re.I)
    pytest_counts = {
        label: sum(
            _integer(value)
            for value in re.findall(rf"\b(\d+)\s+{label}\b", text, re.I)
        )
        for label in ("passed", "failed", "skipped", "error", "errors", "deselected")
    }
    if collected or any(pytest_counts.values()):
        failed = pytest_counts["failed"] + pytest_counts["error"] + pytest_counts["errors"]
        passed = pytest_counts["passed"]
        skipped = pytest_counts["skipped"] + pytest_counts["deselected"]
        discovered = (
            _integer(collected.group(1))
            if collected
            else passed + failed + skipped
        )
        return TestMetrics(
            discovered=discovered,
            executed=passed + failed,
            passed=passed,
            failed=failed,
            skipped=skipped,
            report_format="pytest-text",
        )

    jest_line = re.search(r"\bTests:\s*(.+)$", text, re.I | re.M)
    if jest_line:
        line = jest_line.group(1)
        counts = {
            label: _integer(match.group(1)) if (match := re.search(
                rf"(\d+)\s+{label}", line, re.I
            )) else 0
            for label in ("passed", "failed", "skipped", "total")
        }
        return TestMetrics(
            discovered=counts["total"],
            executed=counts["passed"] + counts["failed"],
            passed=counts["passed"],
            failed=counts["failed"],
            skipped=counts["skipped"],
            report_format="text",
        )

    return TestMetrics(
        report_valid=False,
        failure_reason="No supported test execution count was found.",
        report_format="text",
    )


def _junit_metrics(root: ET.Element, report_format: str) -> TestMetrics:
    suites = [root] if root.tag.rsplit("}", 1)[-1] == "testsuite" else [
        element
        for element in root.iter()
        if element.tag.rsplit("}", 1)[-1] == "testsuite"
    ]
    if not suites:
        return TestMetrics(
            report_valid=False,
            failure_reason="JUnit report contains no testsuite.",
            report_format=report_format,
        )
    # A testsuites root often repeats aggregate counters. Sum leaf suites only.
    leaf_suites = [
        suite
        for suite in suites
        if not any(
            child.tag.rsplit("}", 1)[-1] == "testsuite" for child in suite
        )
    ] or suites
    discovered = sum(_integer(suite.attrib.get("tests")) for suite in leaf_suites)
    failed = sum(
        _integer(suite.attrib.get("failures")) + _integer(suite.attrib.get("errors"))
        for suite in leaf_suites
    )
    skipped = sum(
        _integer(suite.attrib.get("skipped", suite.attrib.get("disabled", 0)))
        for suite in leaf_suites
    )
    passed = max(0, discovered - failed - skipped)
    return TestMetrics(
        discovered=discovered,
        executed=passed + failed,
        passed=passed,
        failed=failed,
        skipped=skipped,
        report_format=report_format,
    )


def _trx_metrics(root: ET.Element) -> TestMetrics:
    counters = next(
        (
            element
            for element in root.iter()
            if element.tag.rsplit("}", 1)[-1] == "Counters"
        ),
        None,
    )
    if counters is None:
        return TestMetrics(
            report_valid=False,
            failure_reason="TRX report contains no Counters element.",
            report_format="trx",
        )
    discovered = _integer(counters.attrib.get("total"))
    executed = _integer(counters.attrib.get("executed"), discovered)
    passed = _integer(counters.attrib.get("passed"))
    failed = _integer(counters.attrib.get("failed"))
    skipped = max(0, discovered - executed)
    return TestMetrics(
        discovered=discovered,
        executed=executed,
        passed=passed,
        failed=failed,
        skipped=skipped,
        report_format="trx",
    )


def _json_metrics(payload: Any, report_format: str) -> TestMetrics:
    if not isinstance(payload, dict):
        return TestMetrics(
            report_valid=False,
            failure_reason="JSON test report is not an object.",
            report_format=report_format,
        )
    if report_format in {"jest-json", "vitest-json"} or any(
        key in payload
        for key in ("numTotalTests", "numPassedTests", "numFailedTests")
    ):
        discovered = _integer(payload.get("numTotalTests"))
        passed = _integer(payload.get("numPassedTests"))
        failed = _integer(payload.get("numFailedTests"))
        skipped = _integer(
            payload.get("numPendingTests", payload.get("numTodoTests", 0))
        )
        return TestMetrics(
            discovered=discovered,
            executed=passed + failed,
            passed=passed,
            failed=failed,
            skipped=skipped,
            report_format=report_format,
        )
    stats = payload.get("stats")
    if report_format == "playwright-json" or isinstance(stats, dict):
        stats = stats if isinstance(stats, dict) else {}
        passed = _integer(stats.get("expected"))
        failed = _integer(stats.get("unexpected"))
        skipped = _integer(stats.get("skipped"))
        flaky = _integer(stats.get("flaky"))
        return TestMetrics(
            discovered=passed + failed + skipped + flaky,
            executed=passed + failed + flaky,
            passed=passed + flaky,
            failed=failed,
            skipped=skipped,
            report_format="playwright-json",
        )
    return TestMetrics(
        report_valid=False,
        failure_reason="Unsupported JSON test report schema.",
        report_format=report_format,
    )


def _flutter_metrics(text: str) -> TestMetrics:
    started: set[str] = set()
    passed = failed = skipped = 0
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        event_type = event.get("type")
        test_id = str(event.get("test", {}).get("id", event.get("testID", "")))
        if event_type == "testStart" and test_id:
            started.add(test_id)
        elif event_type == "testDone":
            result = str(event.get("result", "")).casefold()
            if result in {"success", "passed"}:
                passed += 1
            elif result in {"skipped", "ignored"}:
                skipped += 1
            else:
                failed += 1
    discovered = max(len(started), passed + failed + skipped)
    return TestMetrics(
        discovered=discovered,
        executed=passed + failed,
        passed=passed,
        failed=failed,
        skipped=skipped,
        report_format="flutter-json",
        report_valid=discovered > 0,
        failure_reason=None if discovered > 0 else "No Flutter test events found.",
    )


def _safe_report_path(project: Path, report_path: str) -> Path:
    root = project.resolve()
    candidate = (project / report_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("Test report path escapes the project.") from exc
    return candidate


def evaluate_test_evidence(
    project: Path,
    definition: Any,
    output: str,
    *,
    started_wall_time: float,
) -> TestMetrics:
    """Return normalized, freshness-checked evidence for a test check."""
    command_text = f"{getattr(definition, 'check_id', '')} {definition.command}"
    kind = getattr(definition, "check_kind", "auto")
    is_test = (
        kind == "test"
        or bool(getattr(definition, "require_test_execution", False))
        or bool(getattr(definition, "test_count_pattern", None))
        or bool(getattr(definition, "report_path", None))
        or (
            kind == "auto"
            and bool(
                re.search(
                    r"\b(?:test|pytest|unittest|jest|vitest|playwright|gradle.*test|flutter test|dotnet test)\b",
                    command_text,
                    re.I,
                )
            )
        )
    )
    if not is_test:
        return TestMetrics(report_valid=True)

    report_format = str(getattr(definition, "report_format", "auto"))
    raw_report_path = getattr(definition, "report_path", None)
    if not raw_report_path:
        metrics = (
            _flutter_metrics(output)
            if report_format == "flutter-json"
            else _text_metrics(output)
        )
    else:
        try:
            path = _safe_report_path(project, str(raw_report_path))
        except ValueError as exc:
            return TestMetrics(
                report_path=str(raw_report_path),
                report_format=report_format,
                report_valid=False,
                failure_reason=str(exc),
            )
        if not path.is_file():
            return TestMetrics(
                report_path=str(path),
                report_format=report_format,
                report_valid=False,
                failure_reason="Expected test report does not exist.",
            )
        # Filesystems with coarse timestamps need a small tolerance.
        if path.stat().st_mtime < started_wall_time - 2.0:
            return TestMetrics(
                report_path=str(path),
                report_format=report_format,
                report_valid=False,
                failure_reason="Test report is stale and predates this check.",
            )
        text = path.read_text(encoding="utf-8", errors="replace")
        inferred = report_format
        if inferred == "auto":
            lower_name = path.name.casefold()
            if path.suffix.casefold() == ".trx":
                inferred = "trx"
            elif path.suffix.casefold() == ".xml":
                inferred = (
                    "gradle-junit"
                    if "gradle" in lower_name or "android" in lower_name
                    else "junit-xml"
                )
            elif "playwright" in lower_name:
                inferred = "playwright-json"
            elif "vitest" in lower_name:
                inferred = "vitest-json"
            elif path.suffix.casefold() == ".json":
                inferred = "jest-json"
            else:
                inferred = "text"
        try:
            if inferred in {"junit-xml", "gradle-junit", "android-junit"}:
                metrics = _junit_metrics(ET.fromstring(text), inferred)
            elif inferred == "trx":
                metrics = _trx_metrics(ET.fromstring(text))
            elif inferred in {"jest-json", "vitest-json", "playwright-json"}:
                metrics = _json_metrics(json.loads(text), inferred)
            elif inferred == "flutter-json":
                metrics = _flutter_metrics(text)
            else:
                metrics = _text_metrics(text)
        except (ET.ParseError, json.JSONDecodeError) as exc:
            metrics = TestMetrics(
                report_format=inferred,
                report_valid=False,
                failure_reason=f"Malformed test report: {exc}",
            )
        metrics.report_path = str(path)

    if metrics.executed is None or metrics.executed <= 0:
        metrics.report_valid = False
        metrics.failure_reason = (
            metrics.failure_reason or "Test check executed zero tests."
        )
    if metrics.failed is not None and metrics.failed > 0:
        metrics.report_valid = False
        metrics.failure_reason = (
            metrics.failure_reason or "Test report contains failed tests."
        )
    return metrics
