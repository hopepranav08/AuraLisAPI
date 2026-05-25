"use client";

import { useState, useEffect, useCallback } from "react";

interface FullIncident {
    thread_id: string;
    status: string;
    next: string[];
    endpoint: string;
    classification: string | null;
    severity: string | null;
    is_pii_exposed: boolean;
    pii_findings: string[];
    planned_actions: string[];
    executed_actions: string[];
    reasoning_trace: string[];
    spec_diff: Record<string, unknown> | null;
    github_pr_url: string | null;
    report: {
        executive_summary?: string;
        risk_level?: string;
        recommended_action?: string;
        technical_detail?: string;
    } | null;
}

interface Props {
    threadId: string | null;
    onClose: () => void;
    onApprove: (id: string, notes?: string) => Promise<void>;
    onReject: (id: string, notes?: string) => Promise<void>;
    loadingId: string | null;
}

// ── Helper sub-components ──────────────────────────────────────────────────────

function Section({ title, children }: { title: string; children: React.ReactNode }) {
    return (
        <div style={{ marginBottom: "16px" }}>
            <div style={{
                fontSize: "9px", fontWeight: 700, color: "var(--t3)",
                textTransform: "uppercase", letterSpacing: "0.12em",
                fontFamily: "var(--sans)", marginBottom: "6px",
                borderBottom: "1px solid var(--b1)", paddingBottom: "4px",
            }}>
                {title}
            </div>
            {children}
        </div>
    );
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

// ── 5.3: Vertical timeline for reasoning_trace ────────────────────────────────
function ReasoningTimeline({ steps }: { steps: string[] }) {
    return (
        <div style={{ position: "relative", paddingLeft: "24px" }}>
            {/* Connecting vertical line */}
            <div style={{
                position: "absolute", left: 5, top: 8, bottom: 8,
                width: 1, background: "var(--b2)",
            }} />
            {steps.map((step, i) => (
                <div key={i} style={{ position: "relative", marginBottom: "10px" }}>
                    {/* Step dot */}
                    <div style={{
                        position: "absolute", left: -20, top: 3,
                        width: 8, height: 8,
                        background: i === steps.length - 1 ? "var(--accent)" : "var(--b3)",
                        border: `1px solid ${i === steps.length - 1 ? "var(--accent)" : "var(--b2)"}`,
                        borderRadius: "50%",
                        zIndex: 1,
                    }} />
                    <div style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
                        <span style={{
                            fontSize: "9px", color: "var(--t3)", fontFamily: "var(--mono)",
                            fontWeight: 700, flexShrink: 0, marginTop: 1, minWidth: "18px",
                        }}>
                            {String(i + 1).padStart(2, "0")}
                        </span>
                        <span style={{ fontSize: "11px", color: "var(--t2)", fontFamily: "var(--mono)", lineHeight: 1.55 }}>
                            {step}
                        </span>
                    </div>
                </div>
            ))}
        </div>
    );
}

// ── 5.3: Checklist for planned_actions ───────────────────────────────────────
function ActionChecklist({ planned, executed }: { planned: string[]; executed: string[] }) {
    const executedText = executed.join(" ");
    const visibleActions = planned.filter(a => !a.startsWith("krakend_block:"));
    if (!visibleActions.length) return null;
    return (
        <div>
            {visibleActions.map((action, i) => {
                const key = action.split(":")[0].trim();
                const isDone = executedText.includes(key) || executedText.includes("[enforce]");
                return (
                    <div key={i} style={{
                        display: "flex", alignItems: "flex-start", gap: "8px",
                        padding: "5px 0", borderBottom: "1px solid var(--b1)",
                    }}>
                        <span style={{
                            color: isDone ? "var(--green)" : "var(--t3)",
                            flexShrink: 0, fontSize: "13px", marginTop: -1,
                        }}>
                            {isDone ? "☑" : "☐"}
                        </span>
                        <span style={{
                            fontSize: "11px", fontFamily: "var(--mono)",
                            color: isDone ? "var(--t3)" : "var(--t2)",
                            textDecoration: isDone ? "line-through" : "none",
                            lineHeight: 1.4,
                        }}>
                            {action}
                        </span>
                    </div>
                );
            })}
        </div>
    );
}

// ── 5.3: Diff-style block for spec_diff ──────────────────────────────────────
function SpecDiffBlock({ specDiff }: { specDiff: Record<string, unknown> }) {
    type DiffLine = { text: string; color: string };
    const lines: DiffLine[] = [];

    if (specDiff.source) {
        lines.push({ text: `  source: ${specDiff.source}`, color: "var(--t3)" });
    }
    if ("found_in_spec" in specDiff) {
        if (specDiff.found_in_spec) {
            lines.push({ text: "+ found_in_spec: true", color: "var(--green)" });
        } else {
            lines.push({ text: "- found_in_spec: false  // orphaned endpoint", color: "var(--red)" });
        }
    }
    if ("deprecated" in specDiff) {
        if (specDiff.deprecated === true) {
            lines.push({ text: "- deprecated: true  // zombie candidate", color: "var(--orange)" });
        } else {
            lines.push({ text: "  deprecated: false", color: "var(--t3)" });
        }
    }
    if ("drift_trigger" in specDiff) {
        lines.push({ text: `! drift_trigger: ${specDiff.drift_trigger}`, color: "var(--red)" });
    }

    const responseSchema = specDiff.response_schema;

    return (
        <div style={{
            background: "var(--s2)", border: "1px solid var(--b1)",
            padding: "8px 10px", fontFamily: "var(--mono)", fontSize: "10px", lineHeight: 1.8,
        }}>
            {lines.map((l, i) => (
                <div key={i} style={{ color: l.color }}>{l.text}</div>
            ))}
            {responseSchema !== undefined && (
                <div style={{ marginTop: "6px", borderTop: "1px solid var(--b1)", paddingTop: "6px" }}>
                    <div style={{ color: "var(--t3)", marginBottom: "2px" }}>  response_schema:</div>
                    <pre style={{
                        margin: "0 0 0 12px", color: "var(--t2)", fontSize: "10px",
                        maxHeight: "120px", overflowY: "auto",
                        whiteSpace: "pre-wrap", wordBreak: "break-all",
                    }}>
                        {JSON.stringify(responseSchema, null, 2)}
                    </pre>
                </div>
            )}
        </div>
    );
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function IncidentDetailPanel({ threadId, onClose, onApprove, onReject, loadingId }: Props) {
    const [incident,   setIncident]   = useState<FullIncident | null>(null);
    const [loading,    setLoading]    = useState(false);
    const [error,      setError]      = useState<string | null>(null);
    const [actionType, setActionType] = useState<"approving" | "rejecting" | null>(null);
    // 5.4 — notes for approve/reject
    const [notes,      setNotes]      = useState("");

    const fetchIncident = useCallback(async (id: string) => {
        setLoading(true);
        setError(null);
        try {
            const token = typeof window !== "undefined" ? localStorage.getItem("auralis_brain_token") : null;
            const headers: Record<string, string> = {};
            if (token) headers["Authorization"] = `Bearer ${token}`;
            const res = await fetch(`/brain/incidents/${id}`, { signal: AbortSignal.timeout(5000), headers });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json() as FullIncident;
            setIncident(data);
        } catch (e: unknown) {
            setError(e instanceof Error ? e.message : "Failed to load incident");
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        if (threadId) {
            setIncident(null);
            setActionType(null);
            setNotes("");
            fetchIncident(threadId);
        }
    }, [threadId, fetchIncident]);

    const handleApprove = useCallback(async () => {
        if (!threadId || actionType) return;
        setActionType("approving");
        try {
            await onApprove(threadId, notes);
            await fetchIncident(threadId);
        } finally {
            setActionType(null);
        }
    }, [threadId, actionType, onApprove, fetchIncident, notes]);

    const handleReject = useCallback(async () => {
        if (!threadId || actionType) return;
        setActionType("rejecting");
        try {
            await onReject(threadId, notes);
            await fetchIncident(threadId);
        } finally {
            setActionType(null);
        }
    }, [threadId, actionType, onReject, fetchIncident, notes]);

    if (threadId === null) return null;

    const isAwaiting = incident?.status === "awaiting_approval";
    const isDisabled = loadingId !== null || actionType !== null;
    const specDiff   = incident?.spec_diff as Record<string, unknown> | null | undefined;

    return (
        <>
            {/* Backdrop */}
            <div
                onClick={onClose}
                style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)", zIndex: 200 }}
            />

            {/* Drawer */}
            <div
                onClick={e => e.stopPropagation()}
                style={{
                    position: "fixed", top: 0, right: 0,
                    width: "min(520px, 100vw)", height: "100vh",
                    background: "var(--s1)",
                    borderLeft: "2px solid var(--t1)",
                    zIndex: 201,
                    display: "flex", flexDirection: "column",
                    fontFamily: "var(--mono)",
                }}
            >
                {/* Drawer header */}
                <div style={{
                    display: "flex", alignItems: "center", gap: "8px",
                    padding: "12px 16px",
                    background: "var(--s2)",
                    borderBottom: "1px solid var(--b1)",
                    flexShrink: 0,
                }}>
                    <span style={{ fontSize: "11px", fontWeight: 700, color: "var(--t1)", textTransform: "uppercase", letterSpacing: "0.1em", fontFamily: "var(--sans)" }}>
                        INCIDENT DETAIL
                    </span>
                    {isAwaiting && <span className="badge badge--high">PENDING</span>}
                    {incident && (
                        <span style={{ fontSize: "10px", color: "var(--t3)", fontFamily: "var(--mono)" }}>
                            // {incident.thread_id.slice(0, 16)}
                        </span>
                    )}
                    <div style={{ flex: 1 }} />
                    <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--t2)", fontSize: "16px", lineHeight: 1, padding: "2px 6px" }} title="Close">
                        ✕
                    </button>
                </div>

                {/* Drawer body */}
                <div style={{ flex: 1, overflowY: "auto", padding: "16px" }}>

                    {loading && (
                        <div style={{ display: "flex", justifyContent: "center", padding: "40px 0" }}>
                            <span className="spinner" style={{ width: 20, height: 20 }} />
                        </div>
                    )}

                    {error && (
                        <div style={{ color: "var(--red)", fontSize: "12px", padding: "12px", background: "var(--red-bg)", border: "1px solid var(--b2)" }}>
                            // {error}
                        </div>
                    )}

                    {incident && !loading && (
                        <>
                            {/* ENDPOINT */}
                            <Section title="Endpoint">
                                <div style={{ fontFamily: "var(--mono)", fontSize: "13px", fontWeight: 700, color: "var(--t1)", wordBreak: "break-all", marginBottom: "8px", lineHeight: 1.4 }}>
                                    {incident.endpoint || "—"}
                                </div>
                                <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                                    <ClassBadge cls={incident.classification} />
                                    <SevBadge sev={incident.severity} />
                                    {incident.is_pii_exposed && <span className="badge badge--critical">PII EXPOSED</span>}
                                    {incident.status === "awaiting_approval"
                                        ? <span className="badge badge--high">AWAITING APPROVAL</span>
                                        : <span className="badge badge--ok">{incident.status.toUpperCase()}</span>
                                    }
                                </div>
                            </Section>

                            {/* 5.4 — APPROVE / REJECT with notes */}
                            {isAwaiting && (
                                <Section title="Actions">
                                    <textarea
                                        className="notes-input"
                                        value={notes}
                                        onChange={e => setNotes(e.target.value)}
                                        placeholder="Notes (optional)…"
                                        rows={2}
                                        style={{ marginBottom: "8px" }}
                                    />
                                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px" }}>
                                        <button disabled={isDisabled} onClick={handleApprove} className="btn btn--green btn--sm" style={{ justifyContent: "center", width: "100%", borderRadius: 0 }}>
                                            {actionType === "approving"
                                                ? <><span className="spinner" style={{ width: 10, height: 10 }} />approving…</>
                                                : "// APPROVE + ENFORCE"
                                            }
                                        </button>
                                        <button disabled={isDisabled} onClick={handleReject} className="btn btn--red btn--sm" style={{ justifyContent: "center", width: "100%", borderRadius: 0 }}>
                                            {actionType === "rejecting"
                                                ? <><span className="spinner" style={{ width: 10, height: 10 }} />rejecting…</>
                                                : "// REJECT"
                                            }
                                        </button>
                                    </div>
                                </Section>
                            )}

                            {/* ENFORCEMENT */}
                            {incident.github_pr_url && (
                                <Section title="Enforcement">
                                    <a href={incident.github_pr_url} target="_blank" rel="noopener noreferrer"
                                        style={{ fontSize: "12px", color: "var(--blue)", textDecoration: "none", fontFamily: "var(--mono)", wordBreak: "break-all" }}>
                                        ↗ {incident.github_pr_url.replace("https://github.com/", "")}
                                    </a>
                                </Section>
                            )}

                            {/* AI ANALYSIS */}
                            {incident.report && (
                                <Section title="AI Analysis">
                                    {incident.report.executive_summary && (
                                        <p style={{ fontSize: "12px", color: "var(--t2)", lineHeight: 1.6, marginBottom: "8px", fontFamily: "var(--mono)", margin: "0 0 8px 0" }}>
                                            {incident.report.executive_summary}
                                        </p>
                                    )}
                                    {incident.report.technical_detail && (
                                        <blockquote style={{ fontSize: "11px", color: "var(--t3)", lineHeight: 1.6, borderLeft: "2px solid var(--b2)", paddingLeft: "8px", margin: "0 0 8px 0", fontFamily: "var(--mono)" }}>
                                            {incident.report.technical_detail}
                                        </blockquote>
                                    )}
                                    {incident.report.recommended_action && (
                                        <div style={{ background: "var(--s2)", border: "1px solid var(--b2)", padding: "8px 10px", fontSize: "11px", fontFamily: "var(--mono)" }}>
                                            <span style={{ color: "var(--accent)" }}>next: </span>
                                            <span style={{ color: "var(--t2)" }}>{incident.report.recommended_action}</span>
                                        </div>
                                    )}
                                </Section>
                            )}

                            {/* 5.3 — SPEC DIFF (diff-style block) */}
                            {specDiff && (
                                <Section title="Spec Analysis">
                                    <SpecDiffBlock specDiff={specDiff} />
                                </Section>
                            )}

                            {/* PII DETECTED */}
                            {incident.pii_findings.length > 0 && (
                                <Section title={`PII Detected (${incident.pii_findings.length})`}>
                                    <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                                        {incident.pii_findings.map((f, i) => (
                                            <span key={i} className="badge badge--critical">{f}</span>
                                        ))}
                                    </div>
                                </Section>
                            )}

                            {/* 5.3 — REASONING TRACE (vertical timeline) */}
                            {incident.reasoning_trace.length > 0 && (
                                <Section title={`Reasoning Trace (${incident.reasoning_trace.length} steps)`}>
                                    <ReasoningTimeline steps={incident.reasoning_trace} />
                                </Section>
                            )}

                            {/* 5.3 — PLANNED ACTIONS (checklist) */}
                            {incident.planned_actions.length > 0 && (
                                <Section title="Planned Actions">
                                    <ActionChecklist
                                        planned={incident.planned_actions}
                                        executed={incident.executed_actions}
                                    />
                                </Section>
                            )}

                            {/* EXECUTED ACTIONS */}
                            {incident.executed_actions.length > 0 && (
                                <Section title="Executed Actions">
                                    {incident.executed_actions.map((action, i) => {
                                        const isErr     = action.includes(":ERROR]") || action.includes(":WARN]");
                                        const isEnforce = action.includes("[enforce]");
                                        const color = isErr ? "var(--orange)" : isEnforce ? "var(--green)" : "var(--t3)";
                                        return (
                                            <div key={i} style={{ fontSize: "11px", fontFamily: "var(--mono)", padding: "2px 0", borderBottom: "1px solid var(--b1)", color }}>
                                                {isEnforce ? "✓ " : ""}{action}
                                            </div>
                                        );
                                    })}
                                </Section>
                            )}
                        </>
                    )}
                </div>
            </div>
        </>
    );
}
