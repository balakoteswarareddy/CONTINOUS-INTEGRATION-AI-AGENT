"""Evidence & reporting (Batch 5, Task C; Report Sections 4.1 bullet 4, 5.1).

``evidence_assembler`` assembles the :class:`EvidenceModel` from control-plane
tables ONLY (run record, stage executions, audit trail, PDP decisions,
approvals) — never from free-form runner logs. ``report_models`` projects the
evidence into developer / management / compliance views. ``report_api`` serves
them.
"""

from ci_agent.reporting.evidence_assembler import EvidenceAssembler
from ci_agent.reporting.report_api import router as report_api_router
from ci_agent.reporting.report_models import (
    ComplianceEvidencePackage,
    DeveloperReport,
    ManagementReport,
)

__all__ = [
    "ComplianceEvidencePackage",
    "DeveloperReport",
    "EvidenceAssembler",
    "ManagementReport",
    "report_api_router",
]
