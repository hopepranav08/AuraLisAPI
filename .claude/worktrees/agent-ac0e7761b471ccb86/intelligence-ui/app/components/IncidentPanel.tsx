"use client";

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
}

function classificationBadgeClass(cls: string | null): string {
    switch (cls) {
        case "active_zombie":   return "badge badge--critical";
        case "dormant_zombie":  return "badge badge--high";
        case "shadow":          return "badge badge--medium";
        case "unknown":         return "badge badge--info";
        default:                return "badge";
    }
}

function severityBadgeClass(sev: string | null): string {
    switch (sev) {
        case "critical": return "badge badge--critical";
        case "high":     return "badge badge--high";
        case "medium":   return "badge badge--medium";
        case "low":      return "badge badge--ok";
        default:         return "badge";
    }
}

function classificationLabel(cls: string | null): string {
    switch (cls) {
        case "active_zombie":  return "Zombie";
        case "dormant_zombie": return "Dormant";
        case "shadow":         return "Shadow";
        case "unknown":        return "Unknown";
        default:               return cls ?? "—";
    }
}

export default function IncidentPanel({
    incidents,
    onApprove,
    onReject,
    loadingId,
    selectedEndpoint,
}: Props) {
    // Sort: awaiting approval first, then by endpoint matching selectedEndpoint
    const sorted = [...incidents].sort((a, b) => {
        if (a.status === "awaiting_approval" && b.status !== "awaiting_approval") return -1;
        if (a.status !== "awaiting_approval" && b.status === "awaiting_approval") return 1;
        if (selectedEndpoint) {
            const aMatch = a.endpoint === selectedEndpoint ? -1 : 0;
            const bMatch = b.endpoint === selectedEndpoint ? -1 : 0;
            if (aMatch !== bMatch) return aMatch - bMatch;
        }
        return 0;
    });

    const awaitingCount = incidents.filter(i => i.status === "awaiting_approval").length;

    return (
        <div className="card incidents-panel" style={{ height: "100%", display: "flex", flexDirection: "column" }}>
            <div className="panel-header">
                <span className="panel-header__title">Incidents</span>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                    {awaitingCount > 0 && (
                        <span
                            className="badge badge--high"
                            style={{ fontSize: "0.65rem" }}
                        >
                            {awaitingCount} pending
                        </span>
                    )}
                    <span className="panel-header__count">{incidents.length}</span>
                </div>
            </div>

            {incidents.length === 0 ? (
                <div className="empty-state">
                    <div className="empty-state__icon">🛡</div>
                    <p className="empty-state__text">No incidents detected yet.</p>
                    <p style={{ fontSize: "0.7rem", color: "var(--color-text-dim)" }}>
                        Incidents appear when the AI brain flags an endpoint.
                    </p>
                </div>
            ) : (
                <div className="incidents-list">
                    {sorted.map((incident) => {
                        const isLoading = loadingId === incident.thread_id;
                        const isAwaiting = incident.status === "awaiting_approval";
                        const isHighlighted = selectedEndpoint === incident.endpoint;

                        return (
                            <div
                                key={incident.thread_id}
                                className={`incident-card ${isAwaiting ? "incident-card--awaiting" : "incident-card--completed"}`}
                                style={isHighlighted ? { borderColor: "var(--color-accent)", background: "rgba(245,158,11,0.05)" } : undefined}
                            >
                                <div className="incident-card__path">
                                    {incident.endpoint || "—"}
                                </div>

                                <div className="incident-card__meta">
                                    {incident.classification && (
                                        <span className={classificationBadgeClass(incident.classification)}>
                                            {classificationLabel(incident.classification)}
                                        </span>
                                    )}
                                    {incident.severity && (
                                        <span className={severityBadgeClass(incident.severity)}>
                                            {incident.severity}
                                        </span>
                                    )}
                                    {incident.is_pii_exposed && (
                                        <span className="incident-card__pii">
                                            ⚠ PII
                                        </span>
                                    )}
                                    <span
                                        className="badge"
                                        style={{
                                            background: isAwaiting
                                                ? "rgba(249,115,22,0.12)"
                                                : "rgba(34,197,94,0.08)",
                                            color: isAwaiting
                                                ? "var(--color-warning)"
                                                : "var(--color-text-muted)",
                                            border: "1px solid " + (isAwaiting
                                                ? "rgba(249,115,22,0.25)"
                                                : "rgba(30,45,69,0.8)"),
                                        }}
                                    >
                                        {isAwaiting ? "AWAITING" : "COMPLETED"}
                                    </span>
                                </div>

                                {isAwaiting && (
                                    <div className="incident-card__actions">
                                        <button
                                            className="btn btn--approve"
                                            disabled={isLoading}
                                            onClick={() => onApprove(incident.thread_id)}
                                            title="Approve enforcement — triggers KrakenD quarantine"
                                        >
                                            {isLoading ? (
                                                <><span className="spinner" /> Approving…</>
                                            ) : (
                                                <>
                                                    <svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                                                    </svg>
                                                    Approve
                                                </>
                                            )}
                                        </button>
                                        <button
                                            className="btn btn--reject"
                                            disabled={isLoading}
                                            onClick={() => onReject(incident.thread_id)}
                                            title="Reject enforcement — routes to report only"
                                        >
                                            {isLoading ? (
                                                <><span className="spinner" /> Rejecting…</>
                                            ) : (
                                                <>
                                                    <svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                                        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                                                    </svg>
                                                    Reject
                                                </>
                                            )}
                                        </button>
                                    </div>
                                )}

                                {!isAwaiting && incident.github_pr_url && (
                                    <div style={{ marginTop: "0.5rem" }}>
                                        <a
                                            href={incident.github_pr_url}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="incident-pr-url"
                                        >
                                            <svg width="11" height="11" fill="currentColor" viewBox="0 0 16 16">
                                                <path d="M1.5 1.5a.5.5 0 0 0-.5.5v4a.5.5 0 0 0 1 0V3.207l4.146 4.147a.5.5 0 0 0 .708-.708L2.707 2.5H5.5a.5.5 0 0 0 0-1h-4zM10 5.5a.5.5 0 0 1 .5-.5h4a.5.5 0 0 1 .5.5v4a.5.5 0 0 1-1 0V7.207l-4.146 4.147a.5.5 0 0 1-.708-.708L13.293 6.5H10.5a.5.5 0 0 1-.5-.5z" />
                                            </svg>
                                            View PR
                                        </a>
                                    </div>
                                )}

                                {!isAwaiting && incident.report_summary && (
                                    <div className="incident-report-summary">
                                        {incident.report_summary.executive_summary && (
                                            <p className="incident-report-summary__text">
                                                {incident.report_summary.executive_summary}
                                            </p>
                                        )}
                                        {incident.report_summary.recommended_action && (
                                            <div className="incident-report-summary__action">
                                                <span className="incident-report-summary__action-label">
                                                    Next step
                                                </span>
                                                <span className="incident-report-summary__action-text">
                                                    {incident.report_summary.recommended_action}
                                                </span>
                                            </div>
                                        )}
                                    </div>
                                )}

                                <div
                                    style={{
                                        marginTop: "0.375rem",
                                        fontSize: "0.62rem",
                                        color: "var(--color-text-dim)",
                                        fontFamily: "var(--font-mono)",
                                    }}
                                >
                                    {incident.thread_id.slice(0, 16)}…
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}
