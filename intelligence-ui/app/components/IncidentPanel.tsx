"use client";

import { useState, useCallback } from "react";

export interface IncidentReportSummary {
    executive_summary: string | null;
    risk_level: string | null;
    recommended_action: string | null;
}

export interface Incident {
    thread_id: string;
    endpoint: string;
    classification: string | null;
    severity: string | null;
    is_pii_exposed: boolean;
    status: string;
    github_pr_url: string | null;
    next: string[];
    report_summary: IncidentReportSummary | null;
}

interface Props {
    incidents: Incident[];
    onApprove: (id: string) => Promise<void>;
    onReject: (id: string) => Promise<void>;
    loadingId: string | null;
    selectedEndpoint: string | null;
    onViewDetail: (threadId: string) => void;
}

function classificationColor(cls: string | null): string {
    switch (cls) {
        case "active_zombie":  return "var(--red)";
        case "dormant_zombie": return "var(--orange)";
        case "shadow":         return "var(--blue)";
        default:               return "var(--b3)";
    }
}

function ClassBadge({ cls }: { cls: string | null }) {
    switch (cls) {
        case "active_zombie":  return <span className="badge badge--critical">Active Zombie</span>;
        case "dormant_zombie": return <span className="badge badge--high">Dormant Zombie</span>;
        case "shadow":         return <span className="badge badge--medium">Shadow API</span>;
        default:               return <span className="badge" style={{ color: "var(--t3)", borderColor: "var(--b2)" }}>{cls ?? "unknown"}</span>;
    }
}

function SevBadge({ sev }: { sev: string | null }) {
    if (!sev) return null;
    const cls = sev === "critical" ? "badge--critical" : sev === "high" ? "badge--high" : sev === "medium" ? "badge--medium" : "badge--low";
    return <span className={`badge ${cls}`}>{sev}</span>;
}

// ── IncidentCard ──────────────────────────────────────────────────────────────
// Each card manages its own action state (approving | rejecting | idle)
// so that clicking Approve shows a spinner ONLY on the approve button,
// not on reject — and vice versa. The parent `loadingId` prop still gates
// other cards from firing while any action is in-flight.

function IncidentCard({ incident, onApprove, onReject, loadingId, selectedEndpoint, onViewDetail }: {
    incident: Incident;
    onApprove: (id: string) => Promise<void>;
    onReject: (id: string) => Promise<void>;
    loadingId: string | null;
    selectedEndpoint: string | null;
    onViewDetail: (threadId: string) => void;
}) {
    const [expanded,    setExpanded]    = useState(false);
    // "approving" | "rejecting" | null — tracks WHICH button on THIS card is active
    const [actionType,  setActionType]  = useState<"approving" | "rejecting" | null>(null);

    const isThisCardLoading = loadingId === incident.thread_id;
    const isAwaiting        = incident.status === "awaiting_approval";
    const isSelected        = selectedEndpoint === incident.endpoint;
    const clsColor          = classificationColor(incident.classification);

    // Any card with a different thread_id should be disabled while a sibling is loading
    const isDisabled = loadingId !== null && loadingId !== incident.thread_id;

    const handleApprove = useCallback(async () => {
        if (isThisCardLoading || isDisabled) return;
        setActionType("approving");
        try {
            await onApprove(incident.thread_id);
        } finally {
            setActionType(null);
        }
    }, [isThisCardLoading, isDisabled, onApprove, incident.thread_id]);

    const handleReject = useCallback(async () => {
        if (isThisCardLoading || isDisabled) return;
        setActionType("rejecting");
        try {
            await onReject(incident.thread_id);
        } finally {
            setActionType(null);
        }
    }, [isThisCardLoading, isDisabled, onReject, incident.thread_id]);

    return (
        <div style={{
            background: isSelected ? "rgba(107,222,0,0.07)" : "var(--s1)",
            borderLeft: `3px solid ${isSelected ? "var(--accent)" : clsColor}`,
            borderRight: "1px solid var(--b1)",
            borderTop: "1px solid var(--b1)",
            borderBottom: "1px solid var(--b1)",
            padding: "12px 14px",
            marginBottom: "1px",
            transition: "background 0.12s, border-left-color 0.12s",
            opacity: isDisabled ? 0.6 : 1,
        }}>
            {/* Awaiting indicator */}
            {isAwaiting && (
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                    <span style={{ width: 6, height: 6, background: "var(--orange)", display: "inline-block", flexShrink: 0 }} />
                    <span style={{ fontSize: "10px", fontWeight: 700, color: "var(--orange)", textTransform: "uppercase", letterSpacing: "0.08em", fontFamily: "var(--sans)" }}>
                        AWAITING APPROVAL
                    </span>
                </div>
            )}

            {/* Endpoint */}
            <div style={{ fontFamily: "var(--mono)", fontSize: "12px", fontWeight: 600, color: "var(--t1)", marginBottom: "8px", wordBreak: "break-all", lineHeight: 1.4 }}>
                {incident.endpoint || "—"}
            </div>

            {/* Badges */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: "4px", marginBottom: isAwaiting ? "10px" : "6px" }}>
                <ClassBadge cls={incident.classification} />
                <SevBadge sev={incident.severity} />
                {incident.is_pii_exposed && <span className="badge badge--critical">PII</span>}
                {!isAwaiting && <span className="badge badge--ok">RESOLVED</span>}
            </div>

            {/* Approve / Reject — each button tracks its own loading independently */}
            {isAwaiting && (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px", marginBottom: "8px" }}>
                    {/* APPROVE button */}
                    <button
                        disabled={isThisCardLoading || isDisabled}
                        onClick={handleApprove}
                        className={`btn btn--green btn--sm incident-action-btn${actionType === "approving" ? " incident-action-btn--active" : ""}`}
                        style={{ justifyContent: "center", width: "100%", borderRadius: 0 }}
                        title="Approve: triggers KrakenD 410 enforcement + GitHub PR"
                    >
                        {actionType === "approving" ? (
                            <><span className="spinner" style={{ width: 10, height: 10 }} />approving…</>
                        ) : "// APPROVE + ENFORCE"}
                    </button>

                    {/* REJECT button — spinner ONLY when rejecting, never when approving */}
                    <button
                        disabled={isThisCardLoading || isDisabled}
                        onClick={handleReject}
                        className={`btn btn--red btn--sm incident-action-btn${actionType === "rejecting" ? " incident-action-btn--active" : ""}`}
                        style={{ justifyContent: "center", width: "100%", borderRadius: 0 }}
                        title="Reject: generate report only, no gateway changes"
                    >
                        {actionType === "rejecting" ? (
                            <><span className="spinner" style={{ width: 10, height: 10 }} />rejecting…</>
                        ) : "// REJECT"}
                    </button>
                </div>
            )}

            {/* GitHub PR link */}
            {!isAwaiting && incident.github_pr_url && (
                <a href={incident.github_pr_url} target="_blank" rel="noopener noreferrer"
                    style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: "11px", color: "var(--blue)", textDecoration: "none", marginBottom: "6px", fontFamily: "var(--mono)" }}>
                    ↗ github pr
                </a>
            )}

            {/* AI Report — collapsible */}
            {!isAwaiting && incident.report_summary && (
                <div>
                    <button onClick={() => setExpanded(v => !v)}
                        className="btn btn--sm"
                        style={{ marginBottom: expanded ? "6px" : 0 }}>
                        {expanded ? "▾" : "▸"} AI REPORT
                    </button>
                    {expanded && (
                        <div style={{ background: "var(--s2)", border: "1px solid var(--b2)", padding: "10px", marginTop: "4px" }}>
                            {incident.report_summary.executive_summary && (
                                <p style={{ fontSize: "12px", color: "var(--t2)", lineHeight: 1.6, marginBottom: "6px", fontFamily: "var(--mono)" }}>
                                    {incident.report_summary.executive_summary}
                                </p>
                            )}
                            {incident.report_summary.recommended_action && (
                                <div style={{ fontSize: "11px", color: "var(--t3)", fontFamily: "var(--mono)" }}>
                                    <span style={{ color: "var(--t2)" }}>next: </span>
                                    {incident.report_summary.recommended_action}
                                </div>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* Thread ID + detail link */}
            <div style={{ marginTop: "6px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span style={{ fontSize: "10px", color: "var(--t3)", fontFamily: "var(--mono)" }}>
                    // {incident.thread_id.slice(0, 16)}
                </span>
                <button
                    onClick={() => onViewDetail(incident.thread_id)}
                    className="btn btn--sm"
                    style={{ fontSize: "10px", padding: "1px 6px" }}
                >
                    // DETAILS →
                </button>
            </div>
        </div>
    );
}

export default function IncidentPanel({ incidents, onApprove, onReject, loadingId, selectedEndpoint, onViewDetail }: Props) {
    const sorted = [...incidents].sort((a, b) => {
        if (a.status === "awaiting_approval" && b.status !== "awaiting_approval") return -1;
        if (a.status !== "awaiting_approval" && b.status === "awaiting_approval") return 1;
        if (selectedEndpoint) {
            const am = a.endpoint === selectedEndpoint ? -1 : 0;
            const bm = b.endpoint === selectedEndpoint ? -1 : 0;
            if (am !== bm) return am - bm;
        }
        return 0;
    });
    const awaiting = incidents.filter(i => i.status === "awaiting_approval").length;

    return (
        <div style={{ display: "flex", flexDirection: "column", background: "var(--s1)", border: "1px solid var(--b1)", height: "100%", overflow: "hidden" }}>
            {/* Panel header */}
            <div style={{ background: "var(--s2)", borderBottom: "1px solid var(--b1)", padding: "10px 16px", display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span className="panel-title">INCIDENTS</span>
                    <span className="badge" style={{ color: "var(--t3)", borderColor: "var(--b2)" }}>{incidents.length}</span>
                </div>
                {awaiting > 0 && (
                    <span className="badge badge--high">{awaiting} PENDING</span>
                )}
            </div>

            {/* List */}
            <div style={{ flex: 1, overflowY: "auto", padding: "0", minHeight: 0 }}>
                {incidents.length === 0 ? (
                    <div className="empty-state">
                        <span>// no incidents yet</span>
                    </div>
                ) : (
                    sorted.map(inc => (
                        <IncidentCard
                            key={inc.thread_id}
                            incident={inc}
                            onApprove={onApprove}
                            onReject={onReject}
                            loadingId={loadingId}
                            selectedEndpoint={selectedEndpoint}
                            onViewDetail={onViewDetail}
                        />
                    ))
                )}
            </div>
        </div>
    );
}
