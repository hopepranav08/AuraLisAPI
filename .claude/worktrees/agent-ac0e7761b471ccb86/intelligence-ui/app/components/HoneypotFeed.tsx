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

function relativeTime(timestamp: string): string {
    try {
        const ts = new Date(timestamp).getTime();
        if (isNaN(ts)) return timestamp;
        const diff = Math.floor((Date.now() - ts) / 1000);
        if (diff < 5)   return "just now";
        if (diff < 60)  return `${diff}s ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    } catch {
        return timestamp;
    }
}

function methodClass(method: string): string {
    switch ((method || "").toUpperCase()) {
        case "GET":    return "method--get";
        case "POST":   return "method--post";
        case "DELETE": return "method--delete";
        case "PUT":    return "method--put";
        case "PATCH":  return "method--patch";
        default:       return "method--other";
    }
}

function methodBorderColor(method: string): string {
    switch ((method || "").toUpperCase()) {
        case "GET":    return "var(--color-info)";
        case "POST":   return "var(--color-warning)";
        case "DELETE": return "var(--color-danger)";
        case "PUT":    return "var(--color-accent)";
        case "PATCH":  return "var(--color-ok)";
        default:       return "var(--color-border)";
    }
}

export default function HoneypotFeed({ events }: Props) {
    const feedRef = useRef<HTMLDivElement>(null);

    // Auto-scroll to the top when new events arrive (newest first)
    useEffect(() => {
        if (feedRef.current) {
            feedRef.current.scrollTop = 0;
        }
    }, [events.length]);

    // Show up to 20 entries
    const visible = events.slice(0, 20);

    return (
        <div className="honeypot-panel">
            <div className="honeypot-panel__header">
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <span
                        style={{
                            fontWeight: 700,
                            textTransform: "uppercase",
                            letterSpacing: "0.1em",
                            fontSize: "0.75rem",
                            color: "var(--color-text-muted)",
                        }}
                    >
                        Threat Intelligence
                    </span>
                    {/* Honeypot icon */}
                    <svg
                        width="14"
                        height="14"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="var(--color-warning)"
                        strokeWidth={2}
                        strokeLinecap="round"
                        strokeLinejoin="round"
                    >
                        <path d="M18 8h1a4 4 0 0 1 0 8h-1" />
                        <path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z" />
                        <line x1="6" y1="1" x2="6" y2="4" />
                        <line x1="10" y1="1" x2="10" y2="4" />
                        <line x1="14" y1="1" x2="14" y2="4" />
                    </svg>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    {events.length > 0 && (
                        <div className="live-dot" title="Live threat feed" />
                    )}
                    <span className="panel-header__count">
                        {events.length} hits
                    </span>
                </div>
            </div>

            {events.length === 0 ? (
                <div className="radar-empty">
                    <div className="radar-icon">
                        <div className="radar-icon__sweep" />
                        <div className="radar-icon__dot" />
                    </div>
                    <p className="radar-empty__text">
                        Honeypot active — no probes detected yet
                    </p>
                    <p
                        style={{
                            fontSize: "0.65rem",
                            color: "var(--color-text-dim)",
                            fontFamily: "var(--font-mono)",
                        }}
                    >
                        Listening on quarantined API paths
                    </p>
                </div>
            ) : (
                <div ref={feedRef} className="honeypot-feed">
                    {visible.map((event, idx) => (
                        <div
                            key={`${event.src_ip}-${event.timestamp}-${idx}`}
                            className="feed-entry"
                            style={{
                                // @ts-ignore — CSS custom property for border-left color
                                "--feed-method-color": methodBorderColor(event.method),
                            } as React.CSSProperties}
                        >
                            <span className={`feed-entry__method ${methodClass(event.method)}`}>
                                {(event.method || "?").toUpperCase().slice(0, 6)}
                            </span>

                            <div className="feed-entry__body">
                                <div className="feed-entry__top">
                                    <span className="feed-entry__ip">
                                        {event.src_ip || "unknown"}
                                    </span>
                                    <span className="feed-entry__time">
                                        {relativeTime(event.timestamp)}
                                    </span>
                                </div>

                                <div
                                    className="feed-entry__path"
                                    title={event.path}
                                >
                                    {event.path || "—"}
                                </div>

                                {event.user_agent && (
                                    <div
                                        className="feed-entry__ua"
                                        title={event.user_agent}
                                    >
                                        {event.user_agent}
                                    </div>
                                )}

                                <div
                                    style={{
                                        display: "flex",
                                        alignItems: "center",
                                        gap: "0.75rem",
                                        marginTop: "0.125rem",
                                    }}
                                >
                                    {event.body_len && event.body_len !== "0" && (
                                        <span className="feed-entry__body-len">
                                            {event.body_len}b body
                                        </span>
                                    )}
                                    {event.node_id && event.node_id !== "unknown" && (
                                        <span
                                            style={{
                                                fontSize: "0.62rem",
                                                color: "var(--color-text-dim)",
                                                fontFamily: "var(--font-mono)",
                                            }}
                                        >
                                            node: {event.node_id}
                                        </span>
                                    )}
                                </div>
                            </div>
                        </div>
                    ))}

                    {events.length > 20 && (
                        <div
                            style={{
                                textAlign: "center",
                                fontSize: "0.7rem",
                                color: "var(--color-text-muted)",
                                padding: "0.5rem",
                                fontFamily: "var(--font-mono)",
                            }}
                        >
                            +{events.length - 20} older entries
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
