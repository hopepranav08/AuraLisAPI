"use client";

import { useEffect, useRef } from "react";

export interface HoneypotEvent {
    event_type: string;
    src_ip: string;
    timestamp: string;
    method: string;
    path: string;
    node_id: string;
    body_len: string;
    user_agent: string;
}

interface Props {
    events: HoneypotEvent[];
}

function relativeTime(ts: string): string {
    try {
        const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
        if (isNaN(diff) || diff < 0) return "just now";
        if (diff < 5)    return "just now";
        if (diff < 60)   return `${diff}s ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    } catch { return ts; }
}

const METHOD_STYLES: Record<string, { badgeClass: string }> = {
    GET:    { badgeClass: "badge--medium"   },
    POST:   { badgeClass: "badge--high"     },
    DELETE: { badgeClass: "badge--critical" },
    PUT:    { badgeClass: "badge--purple"   },
    PATCH:  { badgeClass: "badge--ok"       },
    HEAD:   { badgeClass: ""                },
};

export default function HoneypotFeed({ events }: Props) {
    const feedRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        // Only snap to top when user is already near the top (looking at latest events).
        // If they've scrolled down to read older entries, don't interrupt them.
        if (feedRef.current && feedRef.current.scrollTop < 80) {
            feedRef.current.scrollTop = 0;
        }
    }, [events.length]);

    const visible = events.slice(0, 25);
    const methodCounts = events.reduce<Record<string, number>>((acc, ev) => {
        const m = (ev.method || "?").toUpperCase();
        acc[m] = (acc[m] ?? 0) + 1;
        return acc;
    }, {});

    return (
        <div className="panel" style={{ height: "100%" }}>
            {/* Header */}
            <div className="panel-hdr" style={{ flexDirection: "column", alignItems: "flex-start", gap: "8px" }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", width: "100%" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <span className="panel-title">THREAT INTEL</span>
                    </div>
                    <span className={`badge ${events.length > 0 ? "badge--critical" : ""}`} style={events.length === 0 ? { color: "var(--t3)", borderColor: "var(--b2)" } : {}}>
                        {events.length} HITS
                    </span>
                </div>
                {events.length > 0 && (
                    <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                        {Object.entries(methodCounts).map(([m, count]) => {
                            const s = METHOD_STYLES[m] ?? { badgeClass: "" };
                            return (
                                <span key={m} className={`badge ${s.badgeClass}`} style={!s.badgeClass ? { color: "var(--t3)", borderColor: "var(--b2)" } : {}}>
                                    {m} ×{count}
                                </span>
                            );
                        })}
                    </div>
                )}
            </div>

            {/* Feed */}
            {events.length === 0 ? (
                <div className="empty-state">
                    <span style={{ fontSize: "24px" }}>◉</span>
                    <span>// honeypot active — no probes</span>
                </div>
            ) : (
                <div ref={feedRef} style={{ flex: 1, overflowY: "auto", minHeight: 0 }}>
                    {visible.map((ev, idx) => {
                        const method = (ev.method || "?").toUpperCase();
                        const mStyle = METHOD_STYLES[method] ?? { badgeClass: "" };
                        return (
                            <div key={`${ev.src_ip}-${ev.timestamp}-${idx}`}
                                style={{
                                    display: "flex",
                                    gap: "8px",
                                    padding: "6px 10px",
                                    borderBottom: "1px solid var(--b1)",
                                    alignItems: "flex-start",
                                    transition: "background 0.1s",
                                }}
                                onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.background = "var(--s2)"; }}
                                onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.background = ""; }}
                            >
                                <span className={`badge ${mStyle.badgeClass}`} style={!mStyle.badgeClass ? { color: "var(--t3)", borderColor: "var(--b2)" } : { flexShrink: 0, marginTop: 1 }}>
                                    {method.slice(0, 6)}
                                </span>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "2px" }}>
                                        <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--t1)", fontFamily: "var(--mono)" }}>
                                            {ev.src_ip || "unknown"}
                                        </span>
                                        <span style={{ fontSize: "10px", color: "var(--t3)", fontFamily: "var(--mono)", flexShrink: 0, marginLeft: 8 }}>
                                            {relativeTime(ev.timestamp)}
                                        </span>
                                    </div>
                                    <div style={{ fontSize: "11px", color: "var(--red)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={ev.path}>
                                        {ev.path || "—"}
                                    </div>
                                    {ev.user_agent && (
                                        <div style={{ fontSize: "10px", color: "var(--t3)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: "2px", fontFamily: "var(--mono)" }} title={ev.user_agent}>
                                            {ev.user_agent}
                                        </div>
                                    )}
                                </div>
                            </div>
                        );
                    })}
                    {events.length > 25 && (
                        <div style={{ textAlign: "center", fontSize: "10px", color: "var(--t3)", padding: "8px 6px", fontFamily: "var(--mono)", borderTop: "1px dashed var(--b2)" }}>
                            // showing 25 most recent · {events.length - 25} older not shown
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
