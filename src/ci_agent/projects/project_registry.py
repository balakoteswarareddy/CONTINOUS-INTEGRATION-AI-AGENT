"""Project registry persistence layer (Batch 5).

Wraps the Batch 2 :class:`RequirementsResolver` for onboarding and stores
pipeline spec versions content-addressed by sha256 ("spec hash ref").
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.db.models import PipelineSpecRecord, ProjectProfileRecord
from ci_agent.resolver.project_profile import ProjectProfile
from ci_agent.resolver.requirements_resolver import RequirementsResolver


class ProjectNotRegisteredError(LookupError):
    """Raised when a run references a project that was never onboarded."""


class MissingPipelineSpecError(LookupError):
    """Raised when a project has no pipeline spec registered."""


def _canonical_hash(document: dict[str, Any]) -> str:
    """sha256 over canonical (sorted-keys) JSON — the "spec hash ref"."""
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ProjectRegistry:
    """Register projects and pipeline specs; look them up for orchestration."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory
        self._resolver = RequirementsResolver()

    # ------------------------------------------------------------------ writes

    def register_project(
        self,
        *,
        intake_answers: dict[str, Any],
        intake_schema: dict[str, Any],
        repository: str,
    ) -> ProjectProfileRecord:
        """Resolve intake answers via the Batch 2 resolver, persist the profile.

        The registry is keyed by ``repository`` (the full "org/repo" name) —
        the same value the ingress uses as ``run.project_id``. The resolved
        profile is stored verbatim (its intake-derived ``project_id`` is kept
        inside the JSON for traceability).
        """
        org_policy_version = None
        profile = self._resolver.resolve(intake_answers, intake_schema, org_policy_version)
        with self._session_factory() as session:
            record = session.get(ProjectProfileRecord, repository)
            if record is None:
                record = ProjectProfileRecord(project_id=repository)
            record.risk_tier = profile.risk_tier.value
            record.language_stack = profile.language_stack
            record.profile_json = json.dumps(profile.model_dump(mode="json"))
            session.add(record)
            session.commit()
            session.refresh(record)
            return record

    def register_pipeline_spec(
        self, project_id: str, pipeline_spec_document: dict[str, Any]
    ) -> PipelineSpecRecord:
        """Persist a pipeline spec version, content-addressed by its sha256."""
        content_hash = _canonical_hash(pipeline_spec_document)
        with self._session_factory() as session:
            self._require_profile(session, project_id)
            record = PipelineSpecRecord(
                project_id=project_id,
                content_hash=content_hash,
                spec_json=json.dumps(pipeline_spec_document, sort_keys=True),
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record

    # ------------------------------------------------------------------- reads

    def get_profile(self, project_id: str) -> ProjectProfile:
        """Load the registered :class:`ProjectProfile` for a project id."""
        with self._session_factory() as session:
            record = session.get(ProjectProfileRecord, project_id)
            if record is None:
                raise ProjectNotRegisteredError(
                    f"project {project_id!r} is not registered — onboard it via "
                    "POST /admin/projects before dispatching runs"
                )
            return ProjectProfile(**json.loads(record.profile_json))

    def get_profile_record(self, project_id: str) -> ProjectProfileRecord:
        with self._session_factory() as session:
            record = session.get(ProjectProfileRecord, project_id)
            if record is None:
                raise ProjectNotRegisteredError(f"project {project_id!r} is not registered")
            session.expunge(record)
            return record

    def get_pipeline_spec(self, project_id: str, content_hash: str | None = None) -> dict[str, Any]:
        """Latest (or hash-pinned) pipeline spec document for a project."""
        with self._session_factory() as session:
            stmt = (
                select(PipelineSpecRecord)
                .where(PipelineSpecRecord.project_id == project_id)
                .order_by(PipelineSpecRecord.id.desc())
            )
            if content_hash is not None:
                stmt = stmt.where(PipelineSpecRecord.content_hash == content_hash)
            record = session.execute(stmt).scalars().first()
            if record is None:
                hint = f" (hash {content_hash})" if content_hash else ""
                raise MissingPipelineSpecError(
                    f"no pipeline spec registered for project {project_id!r}{hint}"
                )
            document: dict[str, Any] = json.loads(record.spec_json)
            return document

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _require_profile(session: Session, project_id: str) -> None:
        if session.get(ProjectProfileRecord, project_id) is None:
            raise ProjectNotRegisteredError(
                f"project {project_id!r} is not registered — register the project "
                "profile before its pipeline spec"
            )


__all__ = [
    "MissingPipelineSpecError",
    "ProjectNotRegisteredError",
    "ProjectRegistry",
]
