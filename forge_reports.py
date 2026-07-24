from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel, Field


class TestMetrics(BaseModel):
    discovered: int | None = None
    executed: int | None = None
    passed: int | None = None
    failed: int | None = None
    skipped: int | None = None
    report_path: str | None = None
    report_files: list[str] = Field(default_factory=list)
    report_file_count: int = 0
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

    mocha_counts = {
        label: sum(
            _integer(value)
            for value in re.findall(rf"\b(\d+)\s+{label}\b", text, re.I)
        )
        for label in ("passing", "failing", "pending")
    }
    if any(mocha_counts.values()):
        passed = mocha_counts["passing"]
        failed = mocha_counts["failing"]
        skipped = mocha_counts["pending"]
        return TestMetrics(
            discovered=passed + failed + skipped,
            executed=passed + failed,
            passed=passed,
            failed=failed,
            skipped=skipped,
            report_format="mocha-text",
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
    if report_format == "mocha-json":
        stats = stats if isinstance(stats, dict) else {}
        discovered = _integer(stats.get("tests"))
        passed = _integer(stats.get("passes"))
        failed = _integer(stats.get("failures"))
        skipped = _integer(stats.get("pending"))
        if discovered == 0:
            discovered = passed + failed + skipped
        return TestMetrics(
            discovered=discovered,
            executed=passed + failed,
            passed=passed,
            failed=failed,
            skipped=skipped,
            report_format="mocha-json",
        )
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


def _safe_report_glob(report_glob: str) -> str:
    normalized = report_glob.replace("\\", "/").strip()
    path = PurePosixPath(normalized)
    if (
        not normalized
        or "\x00" in normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or any(part == ".." for part in path.parts)
    ):
        raise ValueError("Test report glob must be a safe project-relative pattern.")
    return normalized


def _infer_report_format(path: Path, report_format: str) -> str:
    if report_format != "auto":
        return report_format
    lower_name = path.name.casefold()
    if path.suffix.casefold() == ".trx":
        return "trx"
    if path.suffix.casefold() == ".xml":
        return (
            "gradle-junit"
            if "gradle" in lower_name or "android" in lower_name
            else "junit-xml"
        )
    if "playwright" in lower_name:
        return "playwright-json"
    if "vitest" in lower_name:
        return "vitest-json"
    if path.suffix.casefold() == ".json":
        return "jest-json"
    return "text"


def _parse_report(path: Path, report_format: str) -> TestMetrics:
    text = path.read_text(encoding="utf-8", errors="replace")
    inferred = _infer_report_format(path, report_format)
    try:
        if inferred in {"junit-xml", "gradle-junit", "android-junit"}:
            metrics = _junit_metrics(ET.fromstring(text), inferred)
        elif inferred == "trx":
            metrics = _trx_metrics(ET.fromstring(text))
        elif inferred in {
            "jest-json",
            "vitest-json",
            "playwright-json",
            "mocha-json",
        }:
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
    metrics.report_files = [str(path)]
    metrics.report_file_count = 1
    return metrics


def _aggregate_report_metrics(
    report_root: Path,
    report_files: list[Path],
    report_format: str,
) -> TestMetrics:
    parsed = [_parse_report(path, report_format) for path in report_files]
    invalid = next((metrics for metrics in parsed if not metrics.report_valid), None)
    if invalid is not None:
        return TestMetrics(
            report_path=str(report_root),
            report_files=[str(path) for path in report_files],
            report_file_count=len(report_files),
            report_format=report_format,
            report_valid=False,
            failure_reason=(
                f"Invalid test report {invalid.report_path}: "
                f"{invalid.failure_reason or 'unknown validation failure'}"
            ),
        )

    def total(field: str) -> int | None:
        values = [getattr(metrics, field) for metrics in parsed]
        if any(value is None for value in values):
            return None
        return sum(int(value) for value in values if value is not None)

    return TestMetrics(
        discovered=total("discovered"),
        executed=total("executed"),
        passed=total("passed"),
        failed=total("failed"),
        skipped=total("skipped"),
        report_path=str(report_root),
        report_files=[str(path) for path in report_files],
        report_file_count=len(report_files),
        report_format=report_format,
        report_valid=True,
    )


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
        if report_format == "flutter-json":
            metrics = _flutter_metrics(output)
        elif report_format == "mocha-json":
            try:
                metrics = _json_metrics(json.loads(output), report_format)
            except json.JSONDecodeError as exc:
                metrics = TestMetrics(
                    report_format=report_format,
                    report_valid=False,
                    failure_reason=f"Malformed test report: {exc}",
                )
        else:
            metrics = _text_metrics(output)
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
        if not path.exists():
            return TestMetrics(
                report_path=str(path),
                report_format=report_format,
                report_valid=False,
                failure_reason="Expected test report does not exist.",
            )
        if path.is_dir():
            raw_report_glob = getattr(definition, "report_glob", None)
            default_glob = (
                "TEST-*.xml"
                if report_format in {
                    "auto",
                    "junit-xml",
                    "gradle-junit",
                    "android-junit",
                }
                else "*"
            )
            try:
                report_glob = _safe_report_glob(
                    str(raw_report_glob or default_glob)
                )
                candidates = sorted(
                    candidate
                    for candidate in path.glob(report_glob)
                    if candidate.is_file()
                )
                safe_candidates: list[Path] = []
                project_root = project.resolve()
                for candidate in candidates:
                    resolved = candidate.resolve()
                    resolved.relative_to(project_root)
                    safe_candidates.append(resolved)
            except (OSError, ValueError) as exc:
                return TestMetrics(
                    report_path=str(path),
                    report_format=report_format,
                    report_valid=False,
                    failure_reason=f"Unsafe test report match: {exc}",
                )
            if not safe_candidates:
                return TestMetrics(
                    report_path=str(path),
                    report_format=report_format,
                    report_valid=False,
                    failure_reason="No test report files matched the configured pattern.",
                )
            fresh_candidates = [
                candidate
                for candidate in safe_candidates
                if candidate.stat().st_mtime >= started_wall_time - 2.0
            ]
            if not fresh_candidates:
                return TestMetrics(
                    report_path=str(path),
                    report_files=[str(candidate) for candidate in safe_candidates],
                    report_file_count=0,
                    report_format=report_format,
                    report_valid=False,
                    failure_reason="All matching test reports are stale.",
                )
            metrics = _aggregate_report_metrics(
                path, fresh_candidates, report_format
            )
        elif not path.is_file():
            return TestMetrics(
                report_path=str(path),
                report_format=report_format,
                report_valid=False,
                failure_reason="Expected test report is not a regular file or directory.",
            )
        # Filesystems with coarse timestamps need a small tolerance.
        elif path.stat().st_mtime < started_wall_time - 2.0:
            return TestMetrics(
                report_path=str(path),
                report_format=report_format,
                report_valid=False,
                failure_reason="Test report is stale and predates this check.",
            )
        else:
            metrics = _parse_report(path, report_format)

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
