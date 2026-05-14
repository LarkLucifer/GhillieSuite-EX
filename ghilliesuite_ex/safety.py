"""
Centralized execution safety policy for profile capabilities and HitL gating.

This module keeps the "what is allowed" and "what needs approval" rules in one
place so CLI messaging, runtime behaviour, and tests stay aligned.
"""

from __future__ import annotations

from dataclasses import dataclass

from ghilliesuite_ex.config import normalize_execution_profile


@dataclass(frozen=True)
class ExecutionSafetyPolicy:
    profile: str
    description: str
    targeted_exploitation_enabled: bool
    broad_fuzzing_enabled: bool
    ffuf_enabled: bool
    rsc_probe_enabled: bool
    trufflehog_enabled: bool

    @property
    def force_exploit_allowed(self) -> bool:
        return self.broad_fuzzing_enabled


_PROFILE_POLICIES: dict[str, ExecutionSafetyPolicy] = {
    "vdp-safe": ExecutionSafetyPolicy(
        profile="vdp-safe",
        description="Passive and low-noise checks only. Broad exploitation and brute forcing stay disabled.",
        targeted_exploitation_enabled=False,
        broad_fuzzing_enabled=False,
        ffuf_enabled=False,
        rsc_probe_enabled=False,
        trufflehog_enabled=False,
    ),
    "balanced": ExecutionSafetyPolicy(
        profile="balanced",
        description="Targeted exploitation plus advisory checks. Broad fuzzing remains constrained.",
        targeted_exploitation_enabled=True,
        broad_fuzzing_enabled=False,
        ffuf_enabled=True,
        rsc_probe_enabled=True,
        trufflehog_enabled=True,
    ),
    "aggressive": ExecutionSafetyPolicy(
        profile="aggressive",
        description="Full arsenal enabled, including broad fuzzing paths and aggressive exploit stages.",
        targeted_exploitation_enabled=True,
        broad_fuzzing_enabled=True,
        ffuf_enabled=True,
        rsc_probe_enabled=True,
        trufflehog_enabled=True,
    ),
}


def get_execution_safety_policy(profile: str | None) -> ExecutionSafetyPolicy:
    normalized = normalize_execution_profile(profile)
    return _PROFILE_POLICIES[normalized]


def normalize_tool_label(tool_name: str | None) -> str:
    label = (tool_name or "").strip().lower()
    if not label:
        return ""
    if "(" in label:
        label = label.split("(", 1)[0].strip()
    return label.split()[0] if label else ""


def should_prompt_for_tool(
    tool_name: str | None,
    *,
    safe_mode: bool,
    config_hitl_tools: set[str] | frozenset[str],
    registry_hitl_required: bool = False,
) -> bool:
    """
    Determine whether a tool execution requires explicit operator approval.
    """
    label = (tool_name or "").strip().lower()
    normalized = normalize_tool_label(tool_name)

    if safe_mode:
        return True
    if "ssrf" in label:
        return True
    if normalized in set(config_hitl_tools):
        return True
    if registry_hitl_required:
        return True
    return False

