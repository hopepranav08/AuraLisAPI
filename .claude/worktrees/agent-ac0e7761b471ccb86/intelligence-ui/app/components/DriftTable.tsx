"use client";

export interface EndpointStats {
    endpoint: string;
    current_window: number;
    running_mean: number;
    ph_score: number;
    dormant: boolean;
    dormant_windows: number;
    total_observations: number;
}

interface Props {
    stats: EndpointStats[];
    onSelectEndpoint: (endpoint: string) => void;
    selectedEndpoint: string | null;
}

const PH_ALARM_THRESHOLD = 25;
const PH_BAR_MAX = 30;

function getRowClass(stat: EndpointStats, isSelected: boolean): string {
    if (isSelected) return "row--selected";
    if (stat.ph_score > PH_ALARM_THRESHOLD) return "row--alarm";
    if (stat.dormant) return "row--dormant";
    return "row--ok";
}

function getStatusBadge(stat: EndpointStats): { label: string; cls: string } {
    if (stat.ph_score > PH_ALARM_THRESHOLD && stat.dormant) {
        return { label: "RESURRECT", cls: "badge badge--critical" };
    }
    if (stat.ph_score > PH_ALARM_THRESHOLD) {
        return { label: "ZOMBIE", cls: "badge badge--critical" };
    }
    if (stat.dormant) {
        return { label: "DORMANT", cls: "badge badge--high" };
    }
    if (stat.ph_score === 0 && stat.total_observations > 0) {
        return { label: "OK", cls: "badge badge--ok" };
    }
    return { label: "WATCH", cls: "badge badge--medium" };
}

function PhBar({ score }: { score: number }) {
    const pct = Math.min(100, (score / PH_BAR_MAX) * 100);
    let fillClass = "ph-bar__fill--ok";
    let scoreColor = "var(--color-ok)";
    if (score > PH_ALARM_THRESHOLD) {
        fillClass = "ph-bar__fill--danger";
        scoreColor = "var(--color-danger)";
    } else if (score > 10) {
        fillClass = "ph-bar__fill--warn";
        scoreColor = "var(--color-warning)";
    }

    return (
        <div className="ph-bar-wrap">
            <div className="ph-bar">
                <div
                    className={`ph-bar__fill ${fillClass}`}
                    style={{ width: `${pct}%` }}
                />
            </div>
            <span
                className="ph-score-label"
                style={{ color: scoreColor, fontWeight: score > PH_ALARM_THRESHOLD ? 700 : 400 }}
            >
                {score.toFixed(1)}
            </span>
        </div>
    );
}

export default function DriftTable({ stats, onSelectEndpoint, selectedEndpoint }: Props) {
    // Sort by ph_score descending, then dormant, then alphabetical
    const sorted = [...stats].sort((a, b) => {
        if (b.ph_score !== a.ph_score) return b.ph_score - a.ph_score;
        if (a.dormant !== b.dormant) return a.dormant ? 1 : -1;
        return a.endpoint.localeCompare(b.endpoint);
    });

    return (
        <div className="drift-panel">
            <div className="drift-panel__header">
                <div className="drift-panel__title-group">
                    <div className="live-dot" title="Refreshes every 10 seconds" />
                    <span
                        className="panel-header__title"
                        style={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.1em", fontSize: "0.75rem", color: "var(--color-text-muted)" }}
                    >
                        Endpoint Drift Monitor
                    </span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <span
                        style={{ fontSize: "0.65rem", color: "var(--color-text-muted)", fontFamily: "var(--font-mono)" }}
                    >
                        Page-Hinkley · λ=25
                    </span>
                    <span className="panel-header__count">{sorted.length}</span>
                </div>
            </div>

            {sorted.length === 0 ? (
                <div className="empty-state">
                    <div className="empty-state__icon" style={{ fontSize: "1.5rem" }}>📡</div>
                    <p className="empty-state__text">Waiting for sensor data…</p>
                    <p style={{ fontSize: "0.7rem", color: "var(--color-text-dim)" }}>
                        Data arrives when the eBPF sensor starts publishing events.
                    </p>
                </div>
            ) : (
                <div className="drift-table-wrap">
                    <table className="drift-table">
                        <thead>
                            <tr>
                                <th>Endpoint</th>
                                <th>Traffic</th>
                                <th>Mean</th>
                                <th>PH Score</th>
                                <th>Status</th>
                                <th>Observations</th>
                            </tr>
                        </thead>
                        <tbody>
                            {sorted.map((stat) => {
                                const isSelected = selectedEndpoint === stat.endpoint;
                                const rowClass = getRowClass(stat, isSelected);
                                const badge = getStatusBadge(stat);

                                return (
                                    <tr
                                        key={stat.endpoint}
                                        className={rowClass}
                                        onClick={() => onSelectEndpoint(stat.endpoint)}
                                        title={`Click to highlight ${stat.endpoint} in the graph`}
                                    >
                                        <td
                                            className="cell--endpoint"
                                            title={stat.endpoint}
                                        >
                                            {stat.endpoint}
                                        </td>
                                        <td style={{ color: "var(--color-text)" }}>
                                            {stat.current_window}
                                        </td>
                                        <td
                                            style={{
                                                color: "var(--color-text-muted)",
                                                fontVariantNumeric: "tabular-nums",
                                            }}
                                        >
                                            {stat.running_mean.toFixed(3)}
                                        </td>
                                        <td style={{ minWidth: 120 }}>
                                            <PhBar score={stat.ph_score} />
                                        </td>
                                        <td>
                                            <span className={badge.cls}>{badge.label}</span>
                                        </td>
                                        <td
                                            style={{
                                                color: "var(--color-text-muted)",
                                                fontVariantNumeric: "tabular-nums",
                                            }}
                                        >
                                            {stat.total_observations}
                                            {stat.dormant && stat.dormant_windows > 0 && (
                                                <span
                                                    style={{
                                                        marginLeft: "0.375rem",
                                                        fontSize: "0.65rem",
                                                        color: "var(--color-warning)",
                                                    }}
                                                >
                                                    ({stat.dormant_windows}w idle)
                                                </span>
                                            )}
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}
