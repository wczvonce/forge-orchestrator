from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


ADAPTIVE_SCHEMA_VERSION = 3
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
    last_fingerprint: str | None = None
    last_failure_signature: str | None = None
    closes_milestone: bool = False
    requires_fresh_release_check: bool = False

    @model_validator(mode="after")
    def validate_packet(self) -> "WorkPacket":
        if self.packet_id in self.dependencies:
            raise ValueError("Work packet cannot depend on itself.")
        if self.risk in {"high", "critical"} and self.recommended_worker_profile == "economy":
            raise ValueError("Economy worker cannot be recommended for high-risk work.")
        if self.risk == "critical" and self.check_tier in {"smoke", "targeted"}:
            raise ValueError("Critical work requires milestone or release checks.")
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
    last_fingerprint: str | None = None
    last_failure_signature: str | None = None
    closes_milestone: bool | None = None
    requires_fresh_release_check: bool | None = None
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
    report_validation: Literal["none", "exists", "nonempty", "json"] = "none"

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
        return self


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
    model_argument_allowed: bool = True
    effort_argument_allowed: bool = True
    max_turns_argument_allowed: bool = False


def stable_project_identity(project: Path) -> dict[str, str]:
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
    if updated.work_packets and updated.status == "planning":
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
        acceptance_criteria=criteria[:4],
        difficulty="routine",
        risk="medium",
        recommended_worker_profile=decision.recommended_worker_profile,
        recommended_review_profile=decision.recommended_review_profile,
        check_tier=decision.check_tier,
        max_worker_turns=decision.recommended_worker_max_turns,
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


def resolve_worker_runtime(
    profile: str,
    config: dict[str, Any],
    *,
    unsupported_models: set[str] | None = None,
) -> RoutingRecord:
    unsupported_models = {item.casefold() for item in (unsupported_models or set())}
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
    chosen: dict[str, Any] | None = None
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            continue
        model = str(candidate.get("model") or "").strip()
        if not model:
            continue
        if candidate.get("requires_subscription_confirmation", False) and model.casefold() not in confirmed:
            if fallback_from is None:
                fallback_from = model
            continue
        if model.casefold() in unsupported_models:
            if fallback_from is None:
                fallback_from = model
            continue
        chosen = candidate
        break
    if chosen is None:
        raise RuntimeError(
            f"No subscription-confirmed allowlisted Claude model is available for {profile}; "
            "Forge will not enable usage credits or API billing."
        )
    model = str(chosen["model"])
    effort = str(chosen.get("effort") or profile_config.get("effort") or "medium")
    max_turns = int(profile_config.get("max_turns", 20))
    return RoutingRecord(
        selected_profile=profile,
        selected_model=model,
        selected_effort=effort,
        max_turns=max_turns,
        reason=str(profile_config.get("reason") or f"Allowlisted {profile} profile."),
        fallback_from=fallback_from,
        model_argument_allowed=bool(config.get("claude_supports_model", True)),
        effort_argument_allowed=bool(config.get("claude_supports_effort", True)),
        max_turns_argument_allowed=bool(config.get("claude_supports_max_turns", False)),
    )


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
        "evidence-index.schema.json": EvidenceIndex,
        "chain-budgets.schema.json": ChainBudgets,
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
