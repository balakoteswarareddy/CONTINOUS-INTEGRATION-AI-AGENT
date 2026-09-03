"""Requirements Resolver (Batch 2, Task C; Report Section 4.2).

Turns raw intake answers (structured per
``governance/catalog/intake_schema.yaml`` from Batch 1) into a validated
:class:`ProjectProfile`. This module is deliberately PURE: no database and no
HTTP dependencies, so it is testable in isolation. Persisting profiles is
deferred until the project-onboarding API exists (a later batch — see
NOTES.md).

Answer shape: intake answers may be given flat (``{question_id: value}``) or
nested by section id (``{section_id: {question_id: value}}``); both are
normalized before validation.
"""

from __future__ import annotations

from typing import Any

from ci_agent.governance import load_org_policy_version
from ci_agent.resolver.project_profile import ProjectProfile, compute_risk_tier


class MissingRequirementsError(Exception):
    """Intake answers are missing (or invalid for) one or more required questions.

    Lists EVERY missing/invalid field at once, not just the first.
    """

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("Missing or invalid required intake answers: " + "; ".join(problems))


class ConflictingRequirementsError(Exception):
    """Intake answers violate a documented conflict rule (Batch 2 Task C Step 2)."""

    def __init__(self, conflicts: list[str]) -> None:
        self.conflicts = conflicts
        super().__init__("Conflicting requirements: " + "; ".join(conflicts))


def _flatten_answers(answers: dict[str, Any]) -> dict[str, Any]:
    """Normalize nested-by-section answer dicts into a flat question_id map."""
    flat: dict[str, Any] = {}
    for key, value in answers.items():
        if isinstance(value, dict):
            flat.update(_flatten_answers(value))
        else:
            flat[key] = value
    return flat


def _is_unanswered(value: Any, question_type: str = "string") -> bool:
    """Decide whether an answer counts as "not answered".

    Empty strings/None are unanswered for every type. Empty lists are
    unanswered for scalar types but are a VALID answer for ``string_list``
    questions — an empty allowlist (deny-by-default) is a meaningful,
    intentional answer, not an omission.
    """
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, (list, dict)):
        if question_type == "string_list":
            return False
        return len(value) == 0
    return False


class RequirementsResolver:
    """Normalize + validate intake answers into a canonical ProjectProfile."""

    def resolve(
        self,
        intake_answers: dict[str, Any],
        intake_schema: dict[str, Any],
        policy_version: str | None = None,
    ) -> ProjectProfile:
        """Resolve raw answers into a ProjectProfile.

        Step 1 validates completeness against ``intake_schema`` (all required
        questions answered; enum answers within options), collecting every
        problem before raising :class:`MissingRequirementsError`. Step 2 runs
        the documented conflict rules. Step 3 derives the risk tier. Step 4
        builds the profile, retaining the raw answers verbatim.
        """
        flat = _flatten_answers(intake_answers)

        # ---- Step 1: completeness + enum-option validation against the schema.
        problems: list[str] = []
        for section in intake_schema.get("sections", []):
            for question in section.get("questions", []):
                qid = question["id"]
                qtype = question.get("type", "string")
                answered = qid in flat and not _is_unanswered(flat[qid], qtype)
                if question.get("required", False) and not answered:
                    problems.append(qid)
                    continue
                if answered and question.get("type") == "enum":
                    options = question.get("options", [])
                    if flat[qid] not in options:
                        problems.append(
                            f"{qid} (invalid option {flat[qid]!r}; expected one of {options})"
                        )
        if problems:
            raise MissingRequirementsError(problems)

        # ---- Step 2: deterministic conflict rules.
        conflicts: list[str] = self._detect_conflicts(flat)
        if conflicts:
            raise ConflictingRequirementsError(conflicts)
        warnings: list[str] = self._collect_warnings(flat)

        # ---- Step 3: derive the risk tier from the documented mapping table.
        risk_tier = compute_risk_tier(flat["business_criticality"], flat["data_sensitivity"])
        declared_tier = flat.get("derived_risk_tier")
        if declared_tier is not None and declared_tier != risk_tier.value:
            warnings.append(
                f"intake declared risk tier {declared_tier!r} but deterministic mapping "
                f"computed {risk_tier.value!r}; using the computed tier"
            )

        # ---- Step 4: build the canonical profile.
        pinned_version = policy_version or load_org_policy_version()
        return ProjectProfile(
            project_id=self._project_identifier(flat),
            business_criticality=flat["business_criticality"],
            data_sensitivity=flat["data_sensitivity"],
            risk_tier=risk_tier,
            repo_structure=flat["repo_structure"],
            language_stack=flat["primary_language"],
            runner=flat["runner_os"],
            security_tools=self._collect_security_tools(flat),
            secret_storage=flat["secrets_provider"],
            coverage_requirement=float(flat["minimum_coverage_percent"]),
            artifact_repository=flat["artifact_registry_type"],
            testing_strategy=self._testing_strategy(flat, warnings),
            execution_location=flat["primary_execution_location"],
            policy_version_pinned=pinned_version,
            raw_intake_answers=intake_answers,
            resolution_warnings=warnings,
        )

    # ------------------------------------------------------------ helpers

    @classmethod
    def _detect_conflicts(cls, flat: dict[str, Any]) -> list[str]:
        """Documented conflict rules (Batch 2 Task C Step 2); all reported at once."""
        conflicts: list[str] = []
        sensitivity = flat["data_sensitivity"]
        # Rule 1: confidential/restricted data with no security tooling declared
        # would run scans the security policy mandates with nothing to run them
        # with — a direct contradiction of the Section 6 security family.
        if sensitivity in ("confidential", "restricted") and not cls._collect_security_tools(flat):
            conflicts.append(
                f"data_sensitivity={sensitivity!r} requires at least one security tool "
                "but security_tools is empty"
            )
        # Rule 2: restricted data with no secret storage would force secrets
        # into the repo or pipeline logs — forbidden by Section 7 trust
        # boundaries ("no raw secrets").
        if sensitivity == "restricted" and flat.get("secrets_provider") in ("none", "", None):
            conflicts.append(
                f"data_sensitivity='restricted' requires a secret storage provider "
                f"(got {flat.get('secrets_provider')!r})"
            )
        return conflicts

    @staticmethod
    def _collect_warnings(flat: dict[str, Any]) -> list[str]:
        """Non-fatal flags (Section 4.2 'flag missing or conflicting requirements')."""
        warnings: list[str] = []
        # Rule 3: regulated scope on a low-criticality project is unusual —
        # flag for human review instead of hard-failing.
        regulatory_scope = flat.get("regulatory_scope")
        if (
            isinstance(regulatory_scope, str)
            and regulatory_scope.strip()
            and flat["business_criticality"] == "low"
        ):
            warnings.append(
                f"regulatory_scope={regulatory_scope!r} is set while business_criticality "
                "is 'low'; confirm the classification is correct"
            )
        return warnings

    @staticmethod
    def _project_identifier(flat: dict[str, Any]) -> str:
        """Derive a stable project id.

        Intake has no explicit project_id question, so the repository URL slug
        (org/name for ``https://host/org/name``) is used. An explicit
        ``project_id`` answer wins when present (documented in NOTES.md).
        """
        explicit = flat.get("project_id")
        if isinstance(explicit, str) and explicit.strip():
            return explicit.strip()
        url = str(flat["repository_url"]).rstrip("/")
        without_scheme = url.split("://", 1)[-1]
        parts = [p for p in without_scheme.split("/") if p]
        parts = parts[1:] if len(parts) >= 3 else parts  # drop the host
        slug = "/".join(parts[-2:]) if parts else url
        return slug.removesuffix(".git")

    @staticmethod
    def _collect_security_tools(flat: dict[str, Any]) -> list[str]:
        """Collect declared security tools from the security_tools section."""
        tool_answers = (
            flat.get("sast_tool"),
            flat.get("sca_tool"),
            flat.get("secret_scanning_tool"),
            flat.get("container_image_scanner"),
            flat.get("dast_tool"),
        )
        return [
            str(tool).strip() for tool in tool_answers if isinstance(tool, str) and tool.strip()
        ]

    @staticmethod
    def _testing_strategy(flat: dict[str, Any], warnings: list[str]) -> str:
        """Summarize the mandatory test stages as a deterministic string."""
        parts = [
            name
            for key, name in (
                ("unit_testing_required", "unit"),
                ("integration_testing_required", "integration"),
                ("e2e_testing_required", "e2e"),
            )
            if flat.get(key) is True
        ]
        if not parts:
            warnings.append(
                "no mandatory test stages declared in intake; pipeline will have no test gates"
            )
            return "none"
        return "+".join(parts)
