from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Scenario:
    name: str
    packets: int
    mechanical_packets: int
    routine_packets: int
    complex_packets: int
    milestone_boundaries: int
    repair_packets: int


@dataclass(frozen=True)
class Estimate:
    strategy: str
    codex_calls: int
    claude_calls: int
    full_check_suites: int
    targeted_check_suites: int
    premium_calls: int
    assumptions: list[str]


SCENARIOS = (
    Scenario(
        name="small-crud",
        packets=5,
        mechanical_packets=1,
        routine_packets=3,
        complex_packets=1,
        milestone_boundaries=1,
        repair_packets=1,
    ),
    Scenario(
        name="offline-apartment-manager",
        packets=9,
        mechanical_packets=1,
        routine_packets=5,
        complex_packets=3,
        milestone_boundaries=2,
        repair_packets=2,
    ),
)


def legacy_estimate(scenario: Scenario) -> Estimate:
    worker_calls = scenario.packets + scenario.repair_packets
    return Estimate(
        strategy="compatible-economy-safe",
        codex_calls=worker_calls + 2,
        claude_calls=worker_calls,
        full_check_suites=worker_calls,
        targeted_check_suites=0,
        premium_calls=min(1, scenario.repair_packets),
        assumptions=[
            "One review per worker result plus architecture and final review.",
            "The compatible baseline runs a full check suite after each worker call.",
            "This is a deterministic fake-CLI estimate, not measured token usage.",
        ],
    )


def adaptive_estimate(scenario: Scenario) -> Estimate:
    worker_calls = scenario.packets + scenario.repair_packets
    return Estimate(
        strategy="adaptive-packet",
        codex_calls=worker_calls + 2,
        claude_calls=worker_calls,
        full_check_suites=scenario.milestone_boundaries + 1,
        targeted_check_suites=max(
            0, worker_calls - scenario.milestone_boundaries
        ),
        premium_calls=min(1, max(0, scenario.repair_packets - 1)),
        assumptions=[
            "One review per packet result plus architecture and final review.",
            "Routine packets use targeted checks; milestones and final release use full suites.",
            "No token or elapsed-time percentage is inferred without real reproducible measurements.",
        ],
    )


def run_benchmark() -> dict:
    rows = []
    for scenario in SCENARIOS:
        rows.append(
            {
                "scenario": asdict(scenario),
                "compatible_baseline": asdict(legacy_estimate(scenario)),
                "adaptive": asdict(adaptive_estimate(scenario)),
            }
        )
    return {
        "schema_version": 1,
        "kind": "deterministic-fake-cli-policy-benchmark",
        "measured_tokens": False,
        "measured_elapsed_time": False,
        "percentage_savings_claimed": False,
        "results": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reproducible policy benchmark without model calls."
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = run_benchmark()
    rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
