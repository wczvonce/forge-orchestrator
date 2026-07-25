from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


ADAPTIVE_SCHEMA_VERSION = 4
PACKET_STATUSES = {
    "pending",
    "in_progress",
    "verification",
    "completed",
    "blocked",
    "superseded",
}
CHECK_TIER_ORDER = {"smoke": 0, "targeted": 1, "milestone": 2, "release": 3}
SENSITIVE_WORK_RE = re.compile(
    r"\b(auth(?:entication|orization)?|login|permission|payment|billing|"
    r"migration|encrypt(?:ion)?|concurrenc(?:y|e)|production|data[\s-]?loss|"
    r"prihl[aá]senie|opr[aá]vnenie|bezpe[cč]nos[tť]|platb[ay]|migr[aá]ci[ae]|"
    r"[sš]ifrovanie|s[uú]be[zž]nos[tť]|produkci[ae]|strata\s+d[aá]t)\b",
    re.I,
)
FORBIDDEN_COMMAND_RE = re.compile(
    r"(?i)(?:^|[;&|]\s*)(?:git\s+push|gh\s+pr\s+(?:create|merge)|"
    r"gh\s+release\s+create|npm\s+publish|pnpm\s+publish|"
    r"yarn\s+npm\s+publish|docker\s+push|vercel\b|netlify\s+deploy|"
    r"firebase\s+deploy|fly(?:ctl)?\s+deploy|railway\s+up|heroku\b|"
    r"wrangler\s+deploy|"
    r"kubectl\b|terraform\s+(?:apply|destroy)|aws\b|az\b|gcloud\b|"
    r"rm\s+-rf\b|format(?:\.com)?\b|shutdown\b|restart-computer\b)"
)
NONCACHEABLE_SECURITY_RE = re.compile(
    r"(?i)\b(?:security|safety|vulnerabilit(?:y|ies)|audit|osv|pip-audit|"
    r"bandit|semgrep|trivy|snyk)\b"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    fd, temporary_name = tempfile.mkstemp(
        prefix=f"{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            Path(temporary_name).unlink(missing_ok=True)
        except OSError:
            pass


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WorkPacket(StrictModel):
    packet_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
    title: str = Field(min_length=1, max_length=160)
    objective: str = Field(min_length=1)
    context: str = ""
    packet_type: Literal["code", "docs", "infra"] = "code"
    worker_prompt: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    acceptance_criteria: list[str] = Field(min_length=1, max_length=4)
    status: Literal[
        "pending",
        "in_progress",
        "verification",
        "completed",
        "blocked",
        "superseded",
    ] = "pending"
    difficulty: Literal["mechanical", "routine", "complex", "frontier"] = "routine"
    risk: Literal["low", "medium", "high", "critical"] = "medium"
    recommended_worker_profile: Literal[
        "economy", "standard", "complex", "frontier", "rescue"
    ] = "standard"
    recommended_review_profile: Literal[
        "routine_review", "important_review", "final_review"
    ] = "routine_review"
    check_tier: Literal["smoke", "targeted", "milestone", "release"] = "targeted"
    max_worker_turns: int = Field(default=20, ge=1, le=80)
    expected_paths: list[str] = Field(default_factory=list)
    forbidden_scope: list[str] = Field(default_factory=list)
    attempts: int = Field(default=0, ge=0)
    final_review_recovery_authorized: bool = False
    final_review_recovery_used: bool = False
    last_fingerprint: str | None = None
    last_failure_signature: str | None = None
    closes_milestone: bool = False
    requires_fresh_release_check: bool = False
    completed_by: Literal["forge_checks", "claude_review", "codex_review"] | None = None
    consecutive_check_failures: list[dict[str, Any]] = Field(
        default_factory=list,
        max_length=2,
    )
    claude_review_repair_used: bool = False

    @model_validator(mode="after")
    def validate_packet(self) -> "WorkPacket":
        if self.packet_id in self.dependencies:
            raise ValueError("Work packet cannot depend on itself.")
        if self.risk in {"high", "critical"} and self.recommended_worker_profile == "economy":
            raise ValueError("Economy worker cannot be recommended for high-risk work.")
        if self.risk == "critical" and self.check_tier in {"smoke", "targeted"}:
            raise ValueError("Critical work requires milestone or release checks.")
        if (
            self.final_review_recovery_authorized
            and self.final_review_recovery_used
        ):
            raise ValueError(
                "A final-review recovery cannot be both authorized and consumed."
            )
        return self


class PacketUpdate(StrictModel):
    packet_id: str
    status: Literal[
        "pending",
        "in_progress",
        "verification",
        "completed",
        "blocked",
        "superseded",
    ] | None = None
    objective: str | None = None
    context: str | None = None
    packet_type: Literal["code", "docs", "infra"] | None = None
    worker_prompt: str | None = None
    dependencies: list[str] | None = None
    acceptance_criteria: list[str] | None = Field(default=None, min_length=1, max_length=4)
    difficulty: Literal["mechanical", "routine", "complex", "frontier"] | None = None
    risk: Literal["low", "medium", "high", "critical"] | None = None
    recommended_worker_profile: Literal[
        "economy", "standard", "complex", "frontier", "rescue"
    ] | None = None
    recommended_review_profile: Literal[
        "routine_review", "important_review", "final_review"
    ] | None = None
    check_tier: Literal["smoke", "targeted", "milestone", "release"] | None = None
    max_worker_turns: int | None = Field(default=None, ge=1, le=80)
    expected_paths: list[str] | None = None
    forbidden_scope: list[str] | None = None
    attempts_increment: int = Field(default=0, ge=0, le=1)
    final_review_recovery_authorized: bool | None = None
    final_review_recovery_used: bool | None = None
    last_fingerprint: str | None = None
    last_failure_signature: str | None = None
    closes_milestone: bool | None = None
    requires_fresh_release_check: bool | None = None
    completed_by: Literal["forge_checks", "claude_review", "codex_review"] | None = None
    justification: str = Field(min_length=1)


class PlanPatch(StrictModel):
    add_packets: list[WorkPacket] = Field(default_factory=list, max_length=12)
    update_packets: list[PacketUpdate] = Field(default_factory=list, max_length=12)
    active_packet_id: str | None = None
    append_milestones: list[str] = Field(default_factory=list)
    append_release_gates: list[str] = Field(default_factory=list)
    append_architectural_decisions: list[str] = Field(default_factory=list)
    append_safe_assumptions: list[str] = Field(default_factory=list)
    append_risks: list[str] = Field(default_factory=list)
    explanation: str = ""


class ProjectPlan(StrictModel):
    schema_version: int = ADAPTIVE_SCHEMA_VERSION
    plan_id: str
    project_id: str
    goal_hash: str
    spec_hash: str
    created_at: str
    updated_at: str
    status: Literal["planning", "active", "verification", "done", "blocked"] = "planning"
    active_packet_id: str | None = None
    work_packets: list[WorkPacket] = Field(default_factory=list)
    completed_packet_ids: list[str] = Field(default_factory=list)
    milestones: list[str] = Field(default_factory=list)
    release_gates: list[str] = Field(default_factory=list)
    architectural_decisions: list[str] = Field(default_factory=list)
    safe_assumptions: list[str] = Field(default_factory=list)
    overall_risks: list[str] = Field(default_factory=list)
    technology_layers: list[str] = Field(default_factory=list)
    last_validated_at: str | None = None
    last_validation_summary: str = ""
    check_contract_hash: str | None = None

    @model_validator(mode="after")
    def validate_plan(self) -> "ProjectPlan":
        packet_ids = [packet.packet_id for packet in self.work_packets]
        if len(packet_ids) != len(set(packet_ids)):
            raise ValueError("Duplicate work packet ID.")
        known = set(packet_ids)
        if self.active_packet_id is not None and self.active_packet_id not in known:
            raise ValueError("active_packet_id does not exist.")
        for packet in self.work_packets:
            missing = set(packet.dependencies) - known
            if missing:
                raise ValueError(
                    f"Packet {packet.packet_id} has unknown dependencies: {sorted(missing)}"
                )
        if not set(self.completed_packet_ids).issubset(known):
            raise ValueError("completed_packet_ids contains an unknown packet.")
        by_id = {packet.packet_id: packet for packet in self.work_packets}
        visiting: list[str] = []
        visited: set[str] = set()

        def visit(packet_id: str) -> None:
            if packet_id in visiting:
                start = visiting.index(packet_id)
                cycle = visiting[start:] + [packet_id]
                raise ValueError(
                    "Work packet dependency cycle: " + " -> ".join(cycle)
                )
            if packet_id in visited:
                return
            visiting.append(packet_id)
            for dependency in by_id[packet_id].dependencies:
                visit(dependency)
            visiting.pop()
            visited.add(packet_id)

        for packet_id in packet_ids:
            visit(packet_id)

        unfinished = [
            packet
            for packet in self.work_packets
            if packet.status not in {"completed", "superseded"}
        ]
        if unfinished and self.status not in {"done", "blocked"}:
            ready = [
                packet
                for packet in unfinished
                if packet.status in {"pending", "in_progress", "verification"}
                and all(
                    by_id[dependency].status == "completed"
                    for dependency in packet.dependencies
                )
            ]
            if not ready:
                raise ValueError(
                    "Project plan has unfinished work but no dependency-ready packet."
                )
        return self


class AdaptiveDecision(StrictModel):
    schema_version: int = ADAPTIVE_SCHEMA_VERSION
    status: Literal["continue", "done", "blocked"]
    decision_kind: Literal[
        "implement_packet",
        "repair_packet",
        "verify_packet",
        "complete_packet",
        "replan",
        "complete_project",
        "blocked",
    ] = "implement_packet"
    assessment: str
    active_packet_id: str | None = None
    packet_assessment: str = ""
    next_prompt: str | None = None
    acceptance_criteria: list[str] = Field(default_factory=list, max_length=4)
    risks: list[str] = Field(default_factory=list)
    recommended_worker_profile: Literal[
        "economy", "standard", "complex", "frontier", "rescue"
    ] = "standard"
    recommended_worker_effort: Literal[
        "low", "medium", "high", "xhigh", "max"
    ] = "medium"
    recommended_worker_max_turns: int = Field(default=20, ge=1, le=80)
    recommended_review_profile: Literal[
        "routine_review", "important_review", "final_review"
    ] = "routine_review"
    check_tier: Literal["smoke", "targeted", "milestone", "release"] = "targeted"
    check_ids: list[str] = Field(default_factory=list)
    plan_patch: PlanPatch | None = None
    routing_reason: str = ""
    closes_milestone: bool = False
    requires_release_check: bool = False
    approve_check_contract_drift: bool = False
    check_contract_approval_reason: str = ""

    @model_validator(mode="after")
    def validate_decision(self) -> "AdaptiveDecision":
        if self.status == "continue" and not (self.next_prompt or "").strip():
            raise ValueError("continue requires next_prompt")
        if self.status == "done" and self.decision_kind not in {
            "complete_packet",
            "complete_project",
        }:
            self.decision_kind = "complete_project"
        if self.status == "blocked":
            self.decision_kind = "blocked"
        approval_reason = self.check_contract_approval_reason.strip()
        if self.approve_check_contract_drift:
            if self.status != "continue":
                raise ValueError(
                    "Check-contract drift approval is valid only with status=continue."
                )
            if not approval_reason:
                raise ValueError(
                    "Check-contract drift approval requires a non-empty reason."
                )
            self.check_contract_approval_reason = approval_reason
        elif approval_reason:
            raise ValueError(
                "Check-contract approval reason requires explicit approval=true."
            )
        return self


class CheckDefinition(StrictModel):
    check_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
    command: str = Field(min_length=1)
    tier: Literal["smoke", "targeted", "milestone", "release"] = "targeted"
    timeout_seconds: int = Field(default=900, ge=1, le=7200)
    stacks: list[str] = Field(default_factory=lambda: ["any"])
    when_paths: list[str] = Field(default_factory=list)
    cacheable: bool = False
    required_before_done: bool = False
    test_count_pattern: str | None = None
    report_path: str | None = None
    report_glob: str | None = None
    report_validation: Literal["none", "exists", "nonempty", "json"] = "none"
    check_kind: Literal[
        "auto", "test", "build", "lint", "typecheck", "security", "other"
    ] = "auto"
    report_format: Literal[
        "auto",
        "text",
        "pytest-text",
        "unittest-text",
        "junit-xml",
        "jest-json",
        "vitest-json",
        "playwright-json",
        "mocha-json",
        "mocha-text",
        "gradle-junit",
        "android-junit",
        "trx",
        "flutter-json",
    ] = "auto"
    require_test_execution: bool = False

    @model_validator(mode="after")
    def validate_command(self) -> "CheckDefinition":
        if "\x00" in self.command or "\n" in self.command or "\r" in self.command:
            raise ValueError("Check command must be one line.")
        if FORBIDDEN_COMMAND_RE.search(self.command):
            raise ValueError(f"Unsafe check command rejected: {self.check_id}")
        if self.tier == "release" and self.cacheable:
            raise ValueError("Release checks are never cacheable.")
        if self.cacheable and NONCACHEABLE_SECURITY_RE.search(
            f"{self.check_id} {self.command}"
        ):
            raise ValueError("Security and vulnerability checks are never cacheable.")
        if self.report_glob is not None:
            normalized = self.report_glob.replace("\\", "/").strip()
            if (
                not normalized
                or "\x00" in normalized
                or normalized.startswith("/")
                or re.match(r"^[A-Za-z]:", normalized)
                or any(part == ".." for part in normalized.split("/"))
            ):
                raise ValueError("report_glob must be a safe project-relative pattern.")
        return self


class CheckContract(StrictModel):
    schema_version: int = ADAPTIVE_SCHEMA_VERSION
    check_definitions: list[CheckDefinition] = Field(min_length=1)
    contract_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    source: Literal[
        "explicit_project_config",
        "forge_stack_template",
        "validated_auto_discovery",
        "codex_validated_proposal",
    ]
    stacks: list[str] = Field(default_factory=list)
    created_at: str
    indirect_source_hashes: dict[str, str] = Field(default_factory=dict)
    change_reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_hash(self) -> "CheckContract":
        check_ids = [item.check_id for item in self.check_definitions]
        duplicate_ids = sorted(
            {
                check_id
                for check_id in check_ids
                if check_ids.count(check_id) > 1
            }
        )
        if duplicate_ids:
            raise ValueError(
                "Check contract contains duplicate check IDs: "
                + ", ".join(duplicate_ids)
            )
        if self.contract_hash != check_contract_hash(self):
            raise ValueError("Check contract hash does not match its canonical content.")
        return self


class CheckProposal(StrictModel):
    check_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
    runner: Literal[
        "python-pytest",
        "python-unittest",
        "npm-script",
        "gradle-task",
        "dotnet-test",
        "flutter-test",
    ]
    target: str = Field(min_length=1, max_length=120)
    tier: Literal["smoke", "targeted", "milestone", "release"] = "targeted"
    required_before_done: bool = False
    require_test_execution: bool = False
    report_path: str | None = None
    report_glob: str | None = None
    report_format: Literal[
        "auto",
        "text",
        "pytest-text",
        "unittest-text",
        "junit-xml",
        "jest-json",
        "vitest-json",
        "playwright-json",
        "mocha-json",
        "mocha-text",
        "gradle-junit",
        "android-junit",
        "trx",
        "flutter-json",
    ] = "auto"

    @model_validator(mode="after")
    def validate_target(self) -> "CheckProposal":
        if not re.fullmatch(r"[A-Za-z0-9_./:@-]+", self.target):
            raise ValueError("Check proposal target contains unsafe shell syntax.")
        return self


def materialize_check_proposal(proposal: CheckProposal) -> CheckDefinition:
    """Translate a structured Codex proposal through Forge-owned templates."""
    commands = {
        "python-pytest": f'"{sys.executable}" -m pytest {proposal.target}',
        "python-unittest": f'"{sys.executable}" -m unittest {proposal.target}',
        "npm-script": f"npm run {proposal.target}",
        "gradle-task": f".\\gradlew.bat --no-daemon {proposal.target}",
        "dotnet-test": f"dotnet test {proposal.target}",
        "flutter-test": f"flutter test {proposal.target}",
    }
    runner_format = {
        "python-pytest": "pytest-text",
        "python-unittest": "unittest-text",
        "npm-script": proposal.report_format,
        "gradle-task": proposal.report_format,
        "dotnet-test": proposal.report_format,
        "flutter-test": "flutter-json",
    }
    return CheckDefinition(
        check_id=proposal.check_id,
        command=commands[proposal.runner],
        tier=proposal.tier,
        required_before_done=proposal.required_before_done,
        check_kind="test",
        require_test_execution=proposal.require_test_execution,
        report_path=proposal.report_path,
        report_glob=proposal.report_glob,
        report_format=runner_format[proposal.runner],
    )


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect_indirect_check_sources(
    project: Path, definitions: list[CheckDefinition]
) -> dict[str, str]:
    """Hash scripts and build inputs that can change an indirect check command."""
    project = project.resolve()
    candidates: set[Path] = set()
    package_path = project / "package.json"
    package_payload: dict[str, Any] = {}
    if package_path.is_file():
        try:
            loaded = json.loads(package_path.read_text(encoding="utf-8"))
            package_payload = loaded if isinstance(loaded, dict) else {}
        except (OSError, json.JSONDecodeError):
            package_payload = {}
    for definition in definitions:
        command = definition.command.strip()
        npm_match = re.search(
            r"\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?([A-Za-z0-9:_-]+)\b",
            command,
            re.I,
        )
        if npm_match and package_path.is_file():
            script_name = npm_match.group(1)
            script_value = package_payload.get("scripts", {}).get(script_name)
            if isinstance(script_value, str):
                key = f"package.json#scripts.{script_name}"
                candidates.add(package_path)
                package_payload[key] = script_value
            for name in (
                "package-lock.json",
                "pnpm-lock.yaml",
                "yarn.lock",
                "bun.lock",
                "bun.lockb",
                "vitest.config.js",
                "vitest.config.ts",
                "jest.config.js",
                "jest.config.ts",
                "playwright.config.js",
                "playwright.config.ts",
            ):
                if (project / name).is_file():
                    candidates.add(project / name)
        if re.search(r"\bgradlew(?:\.bat)?\b|\bgradle\b", command, re.I):
            for pattern in (
                "settings.gradle*",
                "build.gradle*",
                "**/build.gradle*",
                "gradle/libs.versions.toml",
                "gradle/wrapper/gradle-wrapper.properties",
            ):
                candidates.update(path for path in project.glob(pattern) if path.is_file())
        if re.search(r"\bpytest\b|\bunittest\b", command, re.I):
            for name in (
                "pyproject.toml",
                "pytest.ini",
                "tox.ini",
                "setup.cfg",
                "requirements.txt",
                "requirements.lock",
                "uv.lock",
                "poetry.lock",
            ):
                if (project / name).is_file():
                    candidates.add(project / name)
    hashes = {
        path.relative_to(project).as_posix(): _file_hash(path)
        for path in sorted(candidates, key=lambda item: str(item).casefold())
    }
    scripts = package_payload.get("scripts", {})
    if isinstance(scripts, dict):
        for definition in definitions:
            match = re.search(
                r"\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?([A-Za-z0-9:_-]+)\b",
                definition.command,
                re.I,
            )
            if match and isinstance(scripts.get(match.group(1)), str):
                value = scripts[match.group(1)]
                hashes[f"package.json#scripts.{match.group(1)}"] = hashlib.sha256(
                    value.encode("utf-8")
                ).hexdigest()
    return hashes


def check_contract_hash(contract: CheckContract | dict[str, Any]) -> str:
    payload = (
        contract.model_dump(mode="json")
        if isinstance(contract, CheckContract)
        else dict(contract)
    )
    payload.pop("contract_hash", None)
    payload.pop("created_at", None)
    serialized = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def build_check_contract(
    project: Path,
    definitions: list[CheckDefinition],
    *,
    source: Literal[
        "explicit_project_config",
        "forge_stack_template",
        "validated_auto_discovery",
        "codex_validated_proposal",
    ],
    stacks: list[str],
    change_reason: str,
) -> CheckContract:
    payload = {
        "schema_version": ADAPTIVE_SCHEMA_VERSION,
        "check_definitions": [
            item.model_dump(mode="json") for item in definitions
        ],
        "source": source,
        "stacks": sorted(set(stacks)),
        "created_at": utc_now(),
        "indirect_source_hashes": collect_indirect_check_sources(
            project, definitions
        ),
        "change_reason": change_reason,
    }
    payload["contract_hash"] = check_contract_hash(payload)
    return CheckContract.model_validate(payload)


def stable_auto_check_id(command: str) -> str:
    """Return the canonical semantic identity for an auto-discovered check."""
    normalized = command.strip()
    lowered = normalized.casefold()
    if normalized == "forge internal bootstrap-integrity":
        return "auto-bootstrap-integrity"
    if lowered == "git diff --check":
        return "auto-git-worktree-whitespace"
    if lowered == "git diff --cached --check":
        return "auto-git-index-whitespace"
    package_match = re.search(
        r"\b(npm|pnpm|yarn|bun)\s+(?:run\s+)?([A-Za-z0-9:_-]+)\b",
        normalized,
        re.I,
    )
    if package_match:
        script = re.sub(
            r"[^a-z0-9]+",
            "-",
            package_match.group(2).casefold(),
        ).strip("-")
        return f"auto-{package_match.group(1).casefold()}-{script}"
    if re.search(r"\bgradlew(?:\.bat)?\b.*\btest\b", normalized, re.I):
        return "auto-gradle-test"
    if re.search(r"\bpytest\b", normalized, re.I):
        return "auto-python-pytest"
    if re.search(r"\bunittest\b", normalized, re.I):
        return "auto-python-unittest"
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"auto-command-{digest}"


def collision_safe_auto_check_id(
    command: str,
    assigned_ids: dict[str, str],
) -> str:
    """Keep the semantic ID unless a distinct command already owns it."""
    normalized = command.strip()
    base_id = stable_auto_check_id(normalized)
    existing_command = assigned_ids.get(base_id)
    if existing_command is None or existing_command == normalized:
        return base_id

    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    for digest_length in (12, 16, 24, 32, 64):
        suffix = f"-{digest[:digest_length]}"
        prefix = base_id[: 80 - len(suffix)].rstrip("-")
        candidate = f"{prefix}{suffix}"
        existing_command = assigned_ids.get(candidate)
        if existing_command is None or existing_command == normalized:
            return candidate
    raise ValueError("Unable to derive a unique stable auto-check ID.")


def validate_contract_update(
    previous: CheckContract,
    proposed: CheckContract,
    *,
    justification: str,
) -> None:
    if not justification.strip():
        raise ValueError("Check contract changes require a justification.")
    old = {item.check_id: item for item in previous.check_definitions}
    new = {item.check_id: item for item in proposed.check_definitions}

    def semantic_payload(definition: CheckDefinition) -> dict[str, Any]:
        payload = definition.model_dump(mode="json")
        payload.pop("check_id", None)
        return payload

    unmatched_new = set(new)
    legacy_identity_migrations: dict[str, str] = {}
    for check_id, definition in old.items():
        if check_id in new:
            unmatched_new.discard(check_id)
            continue
        if re.fullmatch(r"auto-\d{2}", check_id):
            matches = [
                candidate_id
                for candidate_id in unmatched_new
                if semantic_payload(new[candidate_id])
                == semantic_payload(definition)
                and candidate_id == stable_auto_check_id(definition.command)
            ]
            if len(matches) == 1:
                legacy_identity_migrations[check_id] = matches[0]
                unmatched_new.remove(matches[0])

    protected_auto_checks = {
        "auto-bootstrap-integrity": (
            "forge internal bootstrap-integrity",
            "security",
        ),
        "auto-git-worktree-whitespace": ("git diff --check", "auto"),
        "auto-git-index-whitespace": (
            "git diff --cached --check",
            "auto",
        ),
    }
    if (
        previous.source == "validated_auto_discovery"
        or proposed.source == "validated_auto_discovery"
    ):
        for check_id, (command, check_kind) in protected_auto_checks.items():
            protected = new.get(check_id)
            if protected is None:
                raise ValueError(
                    f"Protected Forge check cannot be removed: {check_id}"
                )
            if (
                protected.command != command
                or protected.check_kind != check_kind
                or protected.tier != "smoke"
                or not protected.required_before_done
                or protected.cacheable
            ):
                raise ValueError(
                    f"Protected Forge check cannot be weakened: {check_id}"
                )

    tier_order = {"smoke": 0, "targeted": 1, "milestone": 2, "release": 3}
    for check_id, definition in old.items():
        replacement_id = (
            check_id
            if check_id in new
            else legacy_identity_migrations.get(check_id)
        )
        if definition.required_before_done and replacement_id is None:
            raise ValueError(f"Required check cannot be removed: {check_id}")
        replacement = new.get(replacement_id) if replacement_id else None
        if replacement is None:
            continue
        if replacement_id == check_id and definition.command != replacement.command:
            raise ValueError(
                f"Check command cannot be substituted under the same ID: {check_id}"
            )
        if definition.required_before_done and not replacement.required_before_done:
            raise ValueError(f"required_before_done cannot be disabled: {check_id}")
        if definition.require_test_execution and not replacement.require_test_execution:
            raise ValueError(f"require_test_execution cannot be disabled: {check_id}")
        if tier_order[replacement.tier] > tier_order[definition.tier]:
            raise ValueError(f"Check tier cannot be weakened: {check_id}")
        if definition.check_kind != replacement.check_kind:
            raise ValueError(f"check_kind cannot be changed: {check_id}")
        if definition.stacks != replacement.stacks:
            raise ValueError(f"check stacks cannot be changed: {check_id}")
        if definition.when_paths != replacement.when_paths:
            raise ValueError(f"when_paths cannot be changed: {check_id}")
        if definition.report_format != replacement.report_format:
            raise ValueError(f"report_format cannot be changed: {check_id}")
        if definition.report_path != replacement.report_path:
            raise ValueError(f"report_path cannot be changed: {check_id}")
        if definition.report_glob != replacement.report_glob:
            raise ValueError(f"report_glob cannot be changed: {check_id}")
        if (
            definition.test_count_pattern is not None
            and definition.test_count_pattern != replacement.test_count_pattern
        ):
            raise ValueError(f"test_count_pattern cannot be weakened: {check_id}")
        report_strength = {"none": 0, "exists": 1, "nonempty": 2, "json": 3}
        if (
            report_strength[replacement.report_validation]
            < report_strength[definition.report_validation]
        ):
            raise ValueError(f"report_validation cannot be weakened: {check_id}")
        if not definition.cacheable and replacement.cacheable:
            raise ValueError(f"cacheability cannot be enabled during drift: {check_id}")

    removed_indirect = sorted(
        set(previous.indirect_source_hashes) - set(proposed.indirect_source_hashes)
    )
    if removed_indirect:
        raise ValueError(
            "Indirect check sources cannot be removed during automatic re-lock: "
            + ", ".join(removed_indirect)
        )


class EvidenceIndex(StrictModel):
    schema_version: int = ADAPTIVE_SCHEMA_VERSION
    generated_at: str
    changed_files: list[str] = Field(default_factory=list)
    new_files: list[str] = Field(default_factory=list)
    deleted_files: list[str] = Field(default_factory=list)
    added_lines: int = 0
    removed_lines: int = 0
    diff_hunk_hashes: list[str] = Field(default_factory=list)
    risk_areas: list[str] = Field(default_factory=list)
    worker_summary: str = ""
    failed_checks: list[dict[str, Any]] = Field(default_factory=list)
    successful_check_summary: list[dict[str, Any]] = Field(default_factory=list)
    omitted_success_output: bool = True
    repository_fingerprint: str = ""


class ChainBudgets(StrictModel):
    max_child_runs: int = Field(default=6, ge=0, le=50)
    max_codex_calls: int = Field(default=18, ge=1, le=200)
    max_worker_calls: int = Field(default=16, ge=1, le=200)
    max_elapsed_seconds: int = Field(default=21600, ge=60, le=604800)
    max_full_check_suites: int = Field(default=6, ge=1, le=50)
    max_premium_escalations: int = Field(default=1, ge=0, le=10)
    max_no_progress_events: int = Field(default=3, ge=1, le=20)


class ChainCounters(StrictModel):
    child_runs: int = 0
    codex_calls: int = 0
    worker_calls: int = 0
    elapsed_seconds: float = 0.0
    full_check_suites: int = 0
    premium_escalations: int = 0
    no_progress_events: int = 0


class RoutingRecord(StrictModel):
    schema_version: int = ADAPTIVE_SCHEMA_VERSION
    selected_profile: str
    selected_model: str
    selected_effort: str
    max_turns: int
    reason: str
    fallback_from: str | None = None
    fallback_reason: str | None = None
    candidate_index: int = 0
    requested_turn_budget: int
    cli_turn_limit_enforced: bool
    effective_timeout: int
    max_packet_attempts: int
    max_chain_worker_calls: int
    model_argument_allowed: bool = True
    effort_argument_allowed: bool = True
    max_turns_argument_allowed: bool = False


def stable_project_identity(
    project: Path,
    *,
    create_if_missing: bool = True,
) -> dict[str, str]:
    metadata_path = project / ".forge" / "project.json"
    canonical = str(project.resolve()).casefold()
    canonical_hash = sha256_text(canonical)
    if metadata_path.is_file():
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        if (
            isinstance(payload, dict)
            and isinstance(payload.get("project_id"), str)
            and payload["project_id"].strip()
        ):
            stored_path_hash = payload.get("canonical_path_hash")
            if stored_path_hash and stored_path_hash != canonical_hash:
                raise RuntimeError(
                    "Copied .forge metadata belongs to a different canonical project path."
                )
            return {
                "schema_version": str(payload.get("schema_version", ADAPTIVE_SCHEMA_VERSION)),
                "project_id": payload["project_id"],
                "created_at": str(payload.get("created_at") or ""),
            }
        if not create_if_missing:
            raise RuntimeError(
                "Persistent project identity is invalid; read-only validation "
                "refused to replace it."
            )
    elif not create_if_missing:
        raise RuntimeError(
            "Persistent project identity is missing; read-only validation "
            "refused to create it."
        )
    project_id = f"project-{sha256_text(canonical)[:20]}"
    payload = {
        "schema_version": ADAPTIVE_SCHEMA_VERSION,
        "project_id": project_id,
        "created_at": utc_now(),
        "canonical_path_hash": canonical_hash,
    }
    atomic_json(metadata_path, payload)
    return {
        "schema_version": str(ADAPTIVE_SCHEMA_VERSION),
        "project_id": project_id,
        "created_at": payload["created_at"],
    }


def plan_hash(plan: ProjectPlan) -> str:
    payload = plan.model_dump(mode="json")
    for volatile in ("updated_at", "last_validated_at", "last_validation_summary"):
        payload.pop(volatile, None)
    # Schema-4 plans written before bounded final-review recovery did not
    # contain these keys. Keep the canonical hash byte-compatible while both
    # values are at their default; include either key as soon as recovery state
    # is actually persisted.
    for packet in payload.get("work_packets", []):
        if not packet.get("final_review_recovery_authorized", False):
            packet.pop("final_review_recovery_authorized", None)
        if not packet.get("final_review_recovery_used", False):
            packet.pop("final_review_recovery_used", None)
    return sha256_text(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def load_or_create_plan(project: Path, goal: str) -> ProjectPlan:
    forge_dir = project / ".forge"
    path = forge_dir / "project-plan.json"
    spec_path = project / "SPEC.md"
    spec_hash = sha256_file(spec_path) if spec_path.is_file() else sha256_text("")
    identity = stable_project_identity(project)
    if path.is_file():
        plan = ProjectPlan.model_validate_json(path.read_text(encoding="utf-8"))
        if plan.project_id != identity["project_id"]:
            raise RuntimeError("Project plan identity does not match this project.")
        if plan.goal_hash != sha256_text(goal):
            raise RuntimeError(
                "Existing Forge project plan belongs to a different product goal. "
                "Use an explicit replan instead of silently replacing it."
            )
        return plan
    now = utc_now()
    return ProjectPlan(
        plan_id=f"plan-{sha256_text(identity['project_id'] + goal)[:20]}",
        project_id=identity["project_id"],
        goal_hash=sha256_text(goal),
        spec_hash=spec_hash,
        created_at=now,
        updated_at=now,
        status="planning",
        release_gates=[
            "Fresh release-tier checks pass.",
            "Final read-only Codex review approves the evidence.",
        ],
    )


def save_plan(project: Path, plan: ProjectPlan, snapshot_path: Path | None = None) -> None:
    plan.updated_at = utc_now()
    plan.last_validated_at = plan.updated_at
    plan.last_validation_summary = "Pydantic schema and plan invariants passed."
    validated = ProjectPlan.model_validate(plan.model_dump(mode="json"))
    atomic_json(project / ".forge" / "project-plan.json", validated.model_dump(mode="json"))
    if snapshot_path is not None:
        atomic_json(snapshot_path, validated.model_dump(mode="json"))


def _dedupe_extend(target: list[str], values: list[str]) -> None:
    seen = set(target)
    for value in values:
        clean = value.strip()
        if clean and clean not in seen:
            target.append(clean)
            seen.add(clean)


def apply_plan_patch(plan: ProjectPlan, patch: PlanPatch, *, checks_passed: bool) -> ProjectPlan:
    payload = plan.model_dump(mode="json")
    updated = ProjectPlan.model_validate(payload)
    by_id = {packet.packet_id: packet for packet in updated.work_packets}
    for packet in patch.add_packets:
        if packet.packet_id in by_id:
            raise ValueError(f"plan_patch duplicates packet {packet.packet_id}")
        by_id[packet.packet_id] = packet
        updated.work_packets.append(packet)
    for change in patch.update_packets:
        packet = by_id.get(change.packet_id)
        if packet is None:
            raise ValueError(f"plan_patch references unknown packet {change.packet_id}")
        if packet.status == "completed":
            mutable_fields = {
                name
                for name, value in change.model_dump().items()
                if value not in (None, 0, [], "") and name not in {"packet_id", "justification"}
            }
            if mutable_fields:
                raise ValueError(
                    f"Completed packet {packet.packet_id} cannot be silently rewritten."
                )
        if change.acceptance_criteria is not None:
            old = set(packet.acceptance_criteria)
            new = set(change.acceptance_criteria)
            if not old.issubset(new):
                raise ValueError(
                    f"plan_patch cannot weaken acceptance criteria for {packet.packet_id}"
                )
        if change.status == "completed":
            missing = [
                dep
                for dep in packet.dependencies
                if by_id[dep].status != "completed"
            ]
            if missing:
                raise ValueError(
                    f"Packet {packet.packet_id} cannot complete before dependencies {missing}"
                )
            if not checks_passed:
                raise ValueError(
                    f"Packet {packet.packet_id} cannot complete without passing checks."
                )
        fields = change.model_dump(exclude={"packet_id", "attempts_increment", "justification"})
        for name, value in fields.items():
            if value is not None:
                setattr(packet, name, value)
        packet.attempts += change.attempts_increment
    if patch.active_packet_id is not None:
        if patch.active_packet_id not in by_id:
            raise ValueError("plan_patch active packet does not exist.")
        active = by_id[patch.active_packet_id]
        missing = [dep for dep in active.dependencies if by_id[dep].status != "completed"]
        if missing:
            raise ValueError(
                f"Cannot activate {active.packet_id}; dependencies are incomplete: {missing}"
            )
        updated.active_packet_id = active.packet_id
        if active.status == "pending":
            active.status = "in_progress"
    _dedupe_extend(updated.milestones, patch.append_milestones)
    _dedupe_extend(updated.release_gates, patch.append_release_gates)
    _dedupe_extend(
        updated.architectural_decisions, patch.append_architectural_decisions
    )
    _dedupe_extend(updated.safe_assumptions, patch.append_safe_assumptions)
    _dedupe_extend(updated.overall_risks, patch.append_risks)
    updated.completed_packet_ids = [
        packet.packet_id for packet in updated.work_packets if packet.status == "completed"
    ]
    unfinished = [
        packet
        for packet in updated.work_packets
        if packet.status not in {"completed", "superseded"}
    ]
    dependency_ready = [
        packet
        for packet in unfinished
        if packet.status in {"pending", "in_progress", "verification"}
        and all(
            by_id[dependency].status == "completed"
            for dependency in packet.dependencies
        )
    ]
    current_active = by_id.get(updated.active_packet_id or "")
    if (
        dependency_ready
        and updated.status != "blocked"
        and (
            current_active is None
            or current_active.status in {"blocked", "superseded"}
        )
    ):
        # Do not strand unrelated local work behind a packet-level blocker.
        # Plan order is persistent, so the first ready packet is deterministic.
        replacement = dependency_ready[0]
        updated.active_packet_id = replacement.packet_id
        if replacement.status == "pending":
            replacement.status = "in_progress"
    if unfinished and not dependency_ready:
        # A legitimate model decision may block the only reachable packet (and
        # therefore every packet that depends on it).  Persist that as a clean
        # project-level blocked state instead of letting the final invariant
        # turn a product/dependency blocker into a Forge technical failure.
        updated.status = "blocked"
    elif (
        updated.work_packets
        and updated.status == "planning"
    ) or (
        updated.status == "blocked"
        and patch.active_packet_id is not None
        and dependency_ready
    ):
        # Reopening a blocked plan requires an explicit packet activation.
        updated.status = "active"
    updated.updated_at = utc_now()
    return ProjectPlan.model_validate(updated.model_dump(mode="json"))


def bootstrap_packet(decision: AdaptiveDecision, goal: str) -> WorkPacket:
    criteria = decision.acceptance_criteria or [
        "The assigned coherent implementation result is complete and verified."
    ]
    packet_id = decision.active_packet_id or "packet-001"
    return WorkPacket(
        packet_id=packet_id,
        title="Initial coherent implementation packet",
        objective=decision.next_prompt or goal,
        context="Compatibility bootstrap because the architecture response did not add packets.",
        worker_prompt=decision.next_prompt or goal,
        acceptance_criteria=criteria[:4],
        difficulty="routine",
        risk="medium",
        recommended_worker_profile=decision.recommended_worker_profile,
        recommended_review_profile=decision.recommended_review_profile,
        check_tier=decision.check_tier,
        max_worker_turns=decision.recommended_worker_max_turns,
    )


def validate_lean_initial_plan(packets: list[WorkPacket]) -> None:
    """Fail closed when the one-shot lean architecture is not executable."""
    if not 4 <= len(packets) <= 12:
        raise ValueError(
            "Lean architecture must create 4 to 12 coherent work packets."
        )
    missing_prompts = [
        packet.packet_id
        for packet in packets
        if not (packet.worker_prompt or "").strip()
    ]
    if missing_prompts:
        raise ValueError(
            "Lean architecture requires a complete worker_prompt for every packet; "
            "missing: " + ", ".join(missing_prompts)
        )


def dependency_ready_packet(plan: ProjectPlan) -> WorkPacket | None:
    """Return the first pending dependency-ready packet in persistent plan order."""
    by_id = {packet.packet_id: packet for packet in plan.work_packets}
    return next(
        (
            packet
            for packet in plan.work_packets
            if packet.status == "pending"
            and all(
                by_id[dependency].status == "completed"
                for dependency in packet.dependencies
            )
        ),
        None,
    )


def write_assumptions(project: Path, assumptions: list[str]) -> Path:
    path = project / "ASSUMPTIONS.md"
    lines = [
        "# Safe assumptions",
        "",
        "These assumptions were made by Forge to avoid unnecessary interruption. "
        "They must not authorize financial, legal, production, privacy, or security-sensitive actions.",
        "",
    ]
    lines.extend(f"- {item.strip()}" for item in assumptions if item.strip())
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return path


def choose_codex_profile(
    *,
    phase: str,
    packet: WorkPacket | None,
    repeated_failure_count: int,
    milestone: bool,
) -> tuple[str, str]:
    if phase == "architecture":
        return "architecture", "Initial architecture and persistent plan creation."
    if phase == "final":
        return "final_review", "Fresh release evidence requires final approval."
    if (
        packet is not None
        and (packet.risk in {"high", "critical"} or packet.difficulty in {"complex", "frontier"})
    ) or repeated_failure_count >= 2 or milestone:
        return "important_review", "Risk, complexity, failure history, or milestone requires stronger review."
    return "routine_review", "Small low/medium-risk packet is suitable for economical review."


def choose_worker_profile(
    packet: WorkPacket,
    requested: str,
    *,
    no_progress_count: int,
    repeated_failure_count: int,
    checks_failed: bool,
) -> tuple[str, str]:
    requested = requested if requested in {
        "economy", "standard", "complex", "frontier", "rescue"
    } else packet.recommended_worker_profile
    sensitive = bool(
        SENSITIVE_WORK_RE.search(
            " ".join([packet.title, packet.objective, packet.context, *packet.expected_paths])
        )
    )
    if requested == "economy" and (
        sensitive or packet.risk in {"high", "critical"} or packet.difficulty in {"complex", "frontier"}
    ):
        return "complex", "Economy was rejected for sensitive, high-risk, or complex work."
    if requested == "rescue":
        if no_progress_count > 0 or repeated_failure_count >= 2 or checks_failed:
            return "rescue", "A measured stuck condition permits a controlled strategy change."
        return "complex", "Rescue was rejected because no measured stuck condition exists."
    if requested not in {"rescue", "frontier"}:
        if packet.difficulty == "mechanical" and packet.risk == "low" and not sensitive:
            requested = "economy"
        elif packet.difficulty == "routine" and packet.risk in {"low", "medium"}:
            requested = "standard"
        elif packet.difficulty == "complex" or packet.risk == "high" or sensitive:
            requested = "complex"
        elif packet.difficulty == "frontier" or packet.risk == "critical":
            requested = "frontier"
    if requested == "frontier" and not (
        packet.difficulty == "frontier"
        or packet.risk == "critical"
        or repeated_failure_count >= 2
    ):
        return "complex", "Frontier was rejected because the packet does not justify it."
    return requested, f"Packet difficulty={packet.difficulty}, risk={packet.risk}."


def packet_attempt_budget_exhausted(
    packet: WorkPacket, config: dict[str, Any]
) -> bool:
    maximum = int(config.get("max_packet_attempts", 3))
    if packet.attempts < maximum:
        return False
    return not (
        packet.attempts == maximum
        and packet.final_review_recovery_authorized
        and not packet.final_review_recovery_used
    )


def authorize_final_review_recovery(
    plan: ProjectPlan,
    packet_id: str,
    config: dict[str, Any],
) -> tuple[ProjectPlan, bool]:
    """Persist one extra logical attempt authorized by a green final review."""
    updated = plan.model_copy(deep=True)
    packet = next(
        (item for item in updated.work_packets if item.packet_id == packet_id),
        None,
    )
    if packet is None:
        raise ValueError(f"Unknown work packet {packet_id}.")
    maximum = int(config.get("max_packet_attempts", 3))
    if (
        packet.attempts != maximum
        or packet.final_review_recovery_authorized
        or packet.final_review_recovery_used
    ):
        return plan, False
    packet.final_review_recovery_authorized = True
    updated.updated_at = utc_now()
    return ProjectPlan.model_validate(updated.model_dump(mode="json")), True


def begin_packet_attempt(
    plan: ProjectPlan,
    packet_id: str,
    config: dict[str, Any],
) -> tuple[ProjectPlan, bool]:
    """Record a normal attempt or consume the single authorized recovery."""
    updated = plan.model_copy(deep=True)
    packet = next(
        (item for item in updated.work_packets if item.packet_id == packet_id),
        None,
    )
    if packet is None:
        raise ValueError(f"Unknown work packet {packet_id}.")
    maximum = int(config.get("max_packet_attempts", 3))
    recovery_attempt = packet.attempts >= maximum
    if recovery_attempt:
        if not (
            packet.attempts == maximum
            and packet.final_review_recovery_authorized
            and not packet.final_review_recovery_used
        ):
            raise ValueError(
                f"Packet attempt budget exhausted for {packet.packet_id}: "
                f"{packet.attempts}/{maximum}."
            )
        packet.final_review_recovery_authorized = False
        packet.final_review_recovery_used = True
    packet.attempts += 1
    updated.updated_at = utc_now()
    return (
        ProjectPlan.model_validate(updated.model_dump(mode="json")),
        recovery_attempt,
    )


def refund_packet_attempt(
    plan: ProjectPlan,
    packet_id: str,
    *,
    recovery_attempt: bool,
) -> ProjectPlan:
    """Refund an invocation that produced no valid worker outcome."""
    updated = plan.model_copy(deep=True)
    packet = next(
        (item for item in updated.work_packets if item.packet_id == packet_id),
        None,
    )
    if packet is None:
        raise ValueError(f"Unknown work packet {packet_id}.")
    if packet.attempts <= 0:
        raise ValueError(f"Packet {packet.packet_id} has no attempt to refund.")
    packet.attempts -= 1
    if recovery_attempt:
        if not packet.final_review_recovery_used:
            raise ValueError(
                f"Packet {packet.packet_id} has no consumed recovery to refund."
            )
        packet.final_review_recovery_used = False
        packet.final_review_recovery_authorized = True
    updated.updated_at = utc_now()
    return ProjectPlan.model_validate(updated.model_dump(mode="json"))


def resolve_worker_runtime(
    profile: str,
    config: dict[str, Any],
    *,
    unsupported_models: set[str] | None = None,
    fallback_reasons: dict[str, str] | None = None,
) -> RoutingRecord:
    unsupported_models = {item.casefold() for item in (unsupported_models or set())}
    fallback_reasons = {
        str(key).casefold(): str(value)
        for key, value in (fallback_reasons or {}).items()
    }
    profiles = config.get("adaptive_profiles", {}).get("claude", {})
    profile_config = profiles.get(profile)
    if not isinstance(profile_config, dict):
        raise RuntimeError(f"Claude profile is not allowlisted: {profile}")
    candidates = profile_config.get("candidates", [])
    if not isinstance(candidates, list) or not candidates:
        raise RuntimeError(f"Claude profile has no allowlisted candidates: {profile}")
    confirmed = {
        str(item).casefold()
        for item in config.get("confirmed_subscription_models", [])
    }
    fallback_from: str | None = None
    fallback_reason: str | None = None
    chosen: dict[str, Any] | None = None
    chosen_index = 0
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            continue
        model = str(candidate.get("model") or "").strip()
        if not model:
            continue
        if candidate.get("requires_subscription_confirmation", False) and model.casefold() not in confirmed:
            if fallback_from is None:
                fallback_from = model
                fallback_reason = "subscription_not_confirmed"
            continue
        if model.casefold() in unsupported_models:
            if fallback_from is None:
                fallback_from = model
                fallback_reason = fallback_reasons.get(
                    model.casefold(), "runtime_model_unavailable"
                )
            continue
        chosen = candidate
        chosen_index = index
        break
    if chosen is None:
        raise RuntimeError(
            f"No subscription-confirmed allowlisted Claude model is available for {profile}; "
            "Forge will not enable usage credits or API billing."
        )
    model = str(chosen["model"])
    effort = str(chosen.get("effort") or profile_config.get("effort") or "medium")
    max_turns = int(profile_config.get("max_turns", 20))
    cli_turn_limit = bool(config.get("claude_supports_max_turns", False))
    effective_timeout = int(
        profile_config.get(
            "timeout_seconds", config.get("claude_timeout_seconds", 3600)
        )
    )
    max_packet_attempts = int(
        profile_config.get(
            "max_packet_attempts", config.get("max_packet_attempts", 3)
        )
    )
    max_chain_worker_calls = int(
        config.get("chain_budgets", {}).get("max_worker_calls", 16)
    )
    return RoutingRecord(
        selected_profile=profile,
        selected_model=model,
        selected_effort=effort,
        max_turns=max_turns,
        reason=str(profile_config.get("reason") or f"Allowlisted {profile} profile."),
        fallback_from=fallback_from,
        fallback_reason=fallback_reason,
        candidate_index=chosen_index,
        requested_turn_budget=max_turns,
        cli_turn_limit_enforced=cli_turn_limit,
        effective_timeout=effective_timeout,
        max_packet_attempts=max_packet_attempts,
        max_chain_worker_calls=max_chain_worker_calls,
        model_argument_allowed=bool(config.get("claude_supports_model", True)),
        effort_argument_allowed=bool(config.get("claude_supports_effort", True)),
        max_turns_argument_allowed=cli_turn_limit,
    )


MODEL_FALLBACK_REASONS = {
    "model_unavailable",
    "model_not_included",
    "usage_credits_required",
    "api_billing_required",
    "invalid_model_alias",
}


def classify_worker_termination(
    output: str,
    *,
    exit_code: int,
    timed_out: bool = False,
    final_is_error: bool = False,
) -> str:
    """Classify a Claude CLI termination without authorizing billing changes."""
    if timed_out:
        return "timeout"
    if exit_code == 0 and not final_is_error:
        return "success"
    text = output.casefold()
    if re.search(
        r"\b(?:usage credits?|extra usage|purchase credits?|buy credits?|"
        r"credits? exhausted|credit balance)\b",
        text,
    ):
        return "usage_credits_required"
    if re.search(r"\b(?:api key required|anthropic_api_key|api billing|console billing)\b", text):
        return "api_billing_required"
    if re.search(
        r"\b(?:not included in (?:your|this) (?:plan|subscription)|"
        r"model is not included|upgrade your plan)\b",
        text,
    ):
        return "model_not_included"
    if re.search(
        r"\b(?:invalid (?:model|model alias)|unknown model|unsupported model alias)\b",
        text,
    ):
        return "invalid_model_alias"
    if re.search(
        r"(?:\bmodel\b.{0,80}\b(?:unavailable|not available|not found|unsupported)"
        r"|could not resolve model|no such model)",
        text,
    ):
        return "model_unavailable"
    if re.search(
        r"\b(?:session limit|weekly limit|usage limit|subscription limit|quota exceeded)\b",
        text,
    ):
        return "subscription_limit"
    if re.search(r"\b(?:rate limit|too many requests|429)\b", text):
        return "rate_limit"
    if re.search(
        r"\b(?:not logged in|authentication failed|unauthorized|"
        r"please (?:run|use).{0,20}(?:login|auth)|oauth.*(?:expired|failed))\b",
        text,
    ):
        return "auth_failure"
    if re.search(r"\b(?:sandbox denial|permission denied by sandbox)\b", text):
        return "sandbox_denial"
    if re.search(r"\b(?:max turns?|maximum turns?)\b", text):
        return "max_turns"
    if re.search(r"\b(?:refus(?:al|ed)|cannot assist)\b", text):
        return "refusal"
    return "cli_failure"


def normalize_check_definitions(config: dict[str, Any]) -> list[CheckDefinition]:
    raw = config.get("check_definitions")
    if isinstance(raw, list) and raw:
        return [CheckDefinition.model_validate(item) for item in raw]
    legacy = config.get("checks", [])
    definitions: list[CheckDefinition] = []
    for index, item in enumerate(legacy):
        command = item if isinstance(item, str) else item.get("command", "")
        definitions.append(
            CheckDefinition(
                check_id=f"legacy-{index + 1:02d}",
                command=str(command),
                tier="release",
                timeout_seconds=int(config.get("check_timeout_seconds", 900)),
                required_before_done=True,
            )
        )
    return definitions


def select_check_definitions(
    config: dict[str, Any],
    tier: str,
    *,
    requested_ids: list[str] | None = None,
) -> list[CheckDefinition]:
    if tier not in CHECK_TIER_ORDER:
        raise ValueError(f"Unknown check tier: {tier}")
    definitions = normalize_check_definitions(config)
    by_id = {item.check_id: item for item in definitions}
    if requested_ids:
        unknown = sorted(set(requested_ids) - set(by_id))
        if unknown:
            raise ValueError(f"Codex requested non-allowlisted check IDs: {unknown}")
    selected = [
        item
        for item in definitions
        if CHECK_TIER_ORDER[item.tier] <= CHECK_TIER_ORDER[tier]
        and (not requested_ids or item.check_id in requested_ids or item.required_before_done)
    ]
    if tier == "release":
        required = [item for item in definitions if item.required_before_done]
        for item in required:
            if item.check_id not in {selected_item.check_id for selected_item in selected}:
                selected.append(item)
    return selected


def detect_test_count(output: str, definition: CheckDefinition) -> int | None:
    if not definition.test_count_pattern:
        return None
    match = re.search(definition.test_count_pattern, output, re.I | re.M)
    if not match:
        return None
    value = match.groupdict().get("count") if match.groupdict() else match.group(1)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def validate_check_report(project: Path, definition: CheckDefinition) -> bool:
    if definition.report_validation == "none":
        return True
    if not definition.report_path:
        return False
    report = (project / definition.report_path).resolve()
    try:
        report.relative_to(project.resolve())
    except ValueError:
        return False
    if report.is_dir():
        pattern = definition.report_glob or "*"
        try:
            matches = []
            for candidate in report.glob(pattern):
                resolved = candidate.resolve()
                resolved.relative_to(project.resolve())
                if resolved.is_file():
                    matches.append(resolved)
        except (OSError, ValueError):
            return False
        if definition.report_validation == "exists":
            return bool(matches)
        if definition.report_validation == "nonempty":
            return bool(matches) and all(path.stat().st_size > 0 for path in matches)
        return False
    if not report.is_file():
        return False
    if definition.report_validation == "exists":
        return True
    if definition.report_validation == "nonempty":
        return report.stat().st_size > 0
    if definition.report_validation == "json":
        try:
            json.loads(report.read_text(encoding="utf-8"))
            return True
        except (OSError, json.JSONDecodeError):
            return False
    return False


def check_cache_key(
    definition: CheckDefinition,
    *,
    input_hashes: dict[str, str],
    lockfile_hashes: dict[str, str],
    toolchain_versions: dict[str, str],
    environment_fingerprint: str,
    config_hash: str,
    generated_source_hashes: dict[str, str],
    external_change_fingerprint: str,
) -> str:
    payload = {
        "command": definition.command,
        "input_hashes": input_hashes,
        "lockfile_hashes": lockfile_hashes,
        "toolchain_versions": toolchain_versions,
        "environment_fingerprint": environment_fingerprint,
        "config_hash": config_hash,
        "generated_source_hashes": generated_source_hashes,
        "external_change_fingerprint": external_change_fingerprint,
    }
    return sha256_text(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def build_evidence_index(
    *,
    before_manifest: dict[str, str],
    after_manifest: dict[str, str],
    repository_fingerprint: str,
    diff_text: str = "",
    worker_summary: str = "",
    checks: list[dict[str, Any]] | None = None,
) -> EvidenceIndex:
    before_names = set(before_manifest)
    after_names = set(after_manifest)
    changed = sorted(
        name
        for name in before_names & after_names
        if before_manifest[name] != after_manifest[name]
    )
    new = sorted(after_names - before_names)
    deleted = sorted(before_names - after_names)
    added_lines = 0
    removed_lines = 0
    hunk_hashes: list[str] = []
    current_hunk: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("@@"):
            if current_hunk:
                hunk_hashes.append(sha256_text("\n".join(current_hunk)))
            current_hunk = [line]
        elif current_hunk:
            current_hunk.append(line)
        if line.startswith("+") and not line.startswith("+++"):
            added_lines += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed_lines += 1
    if current_hunk:
        hunk_hashes.append(sha256_text("\n".join(current_hunk)))
    all_changed = changed + new + deleted
    risk_areas = sorted(
        {
            area
            for area in all_changed
            if re.search(
                r"(?i)(auth|security|permission|migration|payment|billing|"
                r"lock|config|secret|credential|database|schema)",
                area,
            )
        }
    )
    failed: list[dict[str, Any]] = []
    successful: list[dict[str, Any]] = []
    for item in checks or []:
        summary = {
            "check_id": item.get("check_id") or item.get("command"),
            "exit_code": item.get("exit_code"),
            "test_count": item.get("test_count"),
            "report_valid": item.get("report_valid"),
        }
        if item.get("exit_code") == 0:
            successful.append(summary)
        else:
            summary["output"] = str(item.get("output") or "")[:4000]
            failed.append(summary)
    return EvidenceIndex(
        generated_at=utc_now(),
        changed_files=changed,
        new_files=new,
        deleted_files=deleted,
        added_lines=added_lines,
        removed_lines=removed_lines,
        diff_hunk_hashes=hunk_hashes,
        risk_areas=risk_areas,
        worker_summary=worker_summary[:3000],
        failed_checks=failed,
        successful_check_summary=successful,
        repository_fingerprint=repository_fingerprint,
    )


def budget_exhaustion(
    counters: ChainCounters, budgets: ChainBudgets
) -> str | None:
    limits = [
        ("child runs", counters.child_runs, budgets.max_child_runs),
        ("Codex calls", counters.codex_calls, budgets.max_codex_calls),
        ("worker calls", counters.worker_calls, budgets.max_worker_calls),
        ("elapsed seconds", counters.elapsed_seconds, budgets.max_elapsed_seconds),
        ("full check suites", counters.full_check_suites, budgets.max_full_check_suites),
        (
            "premium escalations",
            counters.premium_escalations,
            budgets.max_premium_escalations,
        ),
        (
            "no-progress events",
            counters.no_progress_events,
            budgets.max_no_progress_events,
        ),
    ]
    for label, current, maximum in limits:
        if current >= maximum:
            return f"Continuation chain budget exhausted: {label}={current}, limit={maximum}."
    return None


def config_hash(config: dict[str, Any]) -> str:
    return sha256_text(json.dumps(config, ensure_ascii=False, sort_keys=True))


def export_schemas(directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    models = {
        "project-plan.schema.json": ProjectPlan,
        "work-packet.schema.json": WorkPacket,
        "decision.schema.json": AdaptiveDecision,
        "plan-patch.schema.json": PlanPatch,
        "check-definition.schema.json": CheckDefinition,
        "check-contract.schema.json": CheckContract,
        "check-proposal.schema.json": CheckProposal,
        "evidence-index.schema.json": EvidenceIndex,
        "chain-budgets.schema.json": ChainBudgets,
        "routing-record.schema.json": RoutingRecord,
    }
    written: list[Path] = []
    for filename, model in models.items():
        path = directory / filename
        atomic_json(path, model.model_json_schema())
        written.append(path)
    return written


def git_content_manifest(project: Path) -> dict[str, str]:
    manifest: dict[str, str] = {}
    excluded = {".git", ".forge", "node_modules", ".venv", "dist", "build"}
    for path in sorted(project.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(project)
        if any(part in excluded for part in relative.parts):
            continue
        try:
            manifest[relative.as_posix()] = sha256_file(path)
        except OSError:
            continue
    return manifest


def git_baseline(project: Path) -> dict[str, Any]:
    def run(*args: str) -> tuple[int, str]:
        cp = subprocess.run(
            ["git", *args],
            cwd=str(project),
            text=True,
            capture_output=True,
            timeout=60,
            errors="replace",
        )
        return cp.returncode, ((cp.stdout or "") + (cp.stderr or "")).strip()

    head_code, head = run("rev-parse", "HEAD")
    status_code, status = run("status", "--porcelain=v1", "-uall")
    manifest = git_content_manifest(project)
    return {
        "schema_version": ADAPTIVE_SCHEMA_VERSION,
        "captured_at": utc_now(),
        "head": head if head_code == 0 else None,
        "git_status_exit_code": status_code,
        "git_status": status,
        "content_manifest": manifest,
        "content_fingerprint": sha256_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True)
        ),
    }
