# agent/graph.py — LangGraph Incident Response Workflow (Phase 3)
#
# Phase 3 topology:
#   ingest → analyze → plan → [interrupt] → enforce → generate_report → END
#                               └──(low/medium)──────→ generate_report → END
#
# Key changes from Phase 1:
#   - classify + assess_risk nodes replaced by single "analyze" node
#   - New "plan" node formulates GitOps strategy before the interrupt
#   - Interrupt remains before "enforce" — human must approve via API
#   - Conditional routing runs after "plan" (was after "assess_risk")
#
# IMPORTANT — Checkpointer lifecycle:

#   AsyncPostgresSaver is an async context manager that owns a connection pool.
#   It MUST be kept open for the entire application lifetime — do NOT create
#   it inside a function that returns, as the pool closes on function exit.
#
#   Correct pattern (used in main.py lifespan):
#       async with AsyncPostgresSaver.from_conn_string(url) as checkpointer:
#           await checkpointer.setup()
#           app.state.graph = build_graph(checkpointer)
#           yield   ← app runs here; checkpointer stays open
#       # pool closes here on shutdown
from __future__ import annotations

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.checkpoint.memory import MemorySaver

from agent.state import IncidentState
from agent import nodes


def build_graph(checkpointer=None):
    """
    Build and compile the incident response StateGraph.

    Args:
        checkpointer: A LangGraph checkpointer instance (AsyncPostgresSaver for
                      production, MemorySaver for testing, or None for stateless).

    Returns:
        Compiled CompiledGraph ready for ainvoke / astream calls.
    """
    builder = StateGraph(IncidentState)

    # ── Register nodes ────────────────────────────────────────────────────────
    builder.add_node("ingest",           nodes.ingest_node)
    builder.add_node("analyze",          nodes.analyze_node)      # Phase 3: was classify + assess_risk
    builder.add_node("plan",             nodes.plan_node)         # Phase 3: NEW GitOps planner
    builder.add_node("enforce",          nodes.enforce_node)
    builder.add_node("generate_report",  nodes.report_node)

    # ── Define edges ──────────────────────────────────────────────────────────
    builder.set_entry_point("ingest")
    builder.add_edge("ingest",   "analyze")
    builder.add_edge("analyze",  "plan")

    # Conditional routing after plan:
    #   critical/high severity (enforcement_approved=True)  → enforce
    #   medium/low severity (enforcement_approved=False)    → generate_report
    builder.add_conditional_edges(
        "plan",
        nodes.should_enforce,
        {
            "enforce": "enforce",
            "report":  "generate_report",
        },
    )

    builder.add_edge("enforce",         "generate_report")
    builder.add_edge("generate_report", END)

    # ── Compile ───────────────────────────────────────────────────────────────
    # interrupt_before=["enforce"] pauses the graph BEFORE the enforce node.
    # The human reviewer inspects state via GET /incidents/{id} and resumes
    # (approves) via POST /incidents/{id}/approve, or rejects via
    # POST /incidents/{id}/reject which routes around enforce to generate_report.
    compiled = builder.compile(
        checkpointer=checkpointer,
        interrupt_before=["enforce"],
    )
    return compiled


def build_graph_in_memory():
    """
    Build graph with an in-memory checkpointer.
    Used for development, testing, and when PostgreSQL is unavailable.
    State is lost on process restart.
    """
    return build_graph(checkpointer=MemorySaver())


async def setup_postgres_checkpointer(db_url: str) -> AsyncPostgresSaver:
    """
    Create and initialise an AsyncPostgresSaver.

    The returned checkpointer is an async context manager — the CALLER is
    responsible for entering and exiting it (i.e., keeping the pool alive).

    Example in FastAPI lifespan:
        checkpointer = await setup_postgres_checkpointer(url)
        async with checkpointer:
            app.state.graph = build_graph(checkpointer)
            yield
    """
    checkpointer = AsyncPostgresSaver.from_conn_string(db_url)
    return checkpointer
