# agent/state.py — LangGraph State Definition
#
# Rules enforced:
#   - State uses TypedDict (per langgraph-state-management.md)
#   - List fields use Annotated[list, operator.add] reducers (no overwrites)
#   - Graph supports persistence and resumability via PostgreSQL checkpointer
#   - Human-in-the-loop interrupt added before "enforce" node
#
# Phase 3 additions:
#   - is_pii_exposed: boolean gate used by PlannerNode for severity routing
#   - spec_diff: raw diff dict from AnalyzerNode (OpenAPI spec vs live traffic)
#   - github_pr_url: PR link written by EnforcerNode after successful PR creation
from __future__ import annotations

import operator
from typing import Annotated, Any, Literal, Optional
from typing_extensions import TypedDict


class IncidentState(TypedDict):
    """
    Shared state that flows through the LangGraph incident response workflow.
    All list fields use operator.add to accumulate rather than overwrite values,
    as required by the project state management rules.
    """
    # Unique identifier for this incident investigation
    incident_id: str

    # Raw API event that triggered this incident workflow
    raw_event: dict[str, Any]

    # Classification: "shadow" | "active_zombie" | "dormant_zombie" | "unknown"
    classification: Optional[Literal["shadow", "active_zombie", "dormant_zombie", "unknown"]]

    # Risk severity: "critical" | "high" | "medium" | "low"
    severity: Optional[Literal["critical", "high", "medium", "low"]]

    # PII detected in the payload (list accumulates across nodes)
    pii_findings: Annotated[list[str], operator.add]

    # Drift detection scores from Frouros analysis
    drift_scores: Annotated[list[dict[str, Any]], operator.add]

    # Remediation actions planned by the agent
    planned_actions: Annotated[list[str], operator.add]

    # Actions that have been executed (e.g., PR created, 410 route configured)
    executed_actions: Annotated[list[str], operator.add]

    # Human review notes (populated at the interrupt checkpoint)
    human_notes: Annotated[list[str], operator.add]

    # Reasoning trace for explainability
    reasoning_trace: Annotated[list[str], operator.add]

    # Whether this incident is approved for enforcement actions
    enforcement_approved: bool

    # Phase 3 — explicit PII boolean flag (gate for PlannerNode routing)
    is_pii_exposed: bool

    # Phase 3 — raw diff between OpenAPI spec and observed traffic
    # Keys: "missing_from_spec", "deprecated_active", "dormant"
    spec_diff: Optional[dict[str, Any]]

    # Phase 3 — GitHub Pull Request URL written by EnforcerNode
    # None if GITHUB_TOKEN is absent (stub mode) or enforce was not reached
    github_pr_url: Optional[str]

    # Final report markdown
    report: Optional[str]
