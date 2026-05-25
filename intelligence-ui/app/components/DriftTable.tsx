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

const PH_ALARM = 25;

function getStatus(stat: EndpointStats): { label: string; badgeClass: string } {
    if (stat.ph_score > PH_ALARM && stat.dormant) return { label: "RESURRECT", badgeClass: "badge--critical" };
    if (stat.ph_score > PH_ALARM)                 return { label: "ZOMBIE",    badgeClass: "badge--critical" };
    if (stat.dormant)                              return { label: "DORMANT",   badgeClass: "badge--high"     };
    if (stat.total_observations > 0 && stat.ph_score === 0) return { label: "HEALTHY", badgeClass: "badge--ok" };
    return { label: "WATCH", badgeClass: "badge--accent" };
}

function PhBar({ score }: { score: number }) {
    const pct      = Math.min(100, (score / 30) * 100);
    const fillClass = score > PH_ALARM ? "score-bar__fill--red" : score > 10 ? "score-bar__fill--orange" : "score-bar__fill--green";
    const color     = score > PH_ALARM ? "var(--red)" : score > 10 ? "var(--orange)" : "var(--green)";
    return (
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div className="score-bar" style={{ flex: 1, height: 4 }}>
                <div className={`score-bar__fill ${fillClass}`} style={{ width: `${pct}%` }} />
            </div>
            <span style={{ fontSize: "11px", fontFamily: "var(--mono)", color, fontWeight: score > PH_ALARM ? 700 : 500, minWidth: 32, textAlign: "right" }}>
                {score.toFixed(1)}
            </span>
        </div>
    );
}

export default function DriftTable({ stats, onSelectEndpoint, selectedEndpoint }: Props) {
    const sorted = [...stats].sort((a, b) => {
        if (b.ph_score !== a.ph_score) return b.ph_score - a.ph_score;
        if (a.dormant !== b.dormant) return a.dormant ? 1 : -1;
        return a.endpoint.localeCompare(b.endpoint);
    });

    return (
        <div className="panel" style={{ height: "100%" }}>
            {/* Header */}
            <div className="panel-hdr">
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span className="panel-title">ENDPOINT DRIFT</span>
                    <span className="badge" style={{ color: "var(--t3)", borderColor: "var(--b2)" }}>{sorted.length}</span>
                </div>
                <span style={{ fontSize: "10px", color: "var(--t3)", fontFamily: "var(--mono)" }}>
                    PH λ={PH_ALARM}
                </span>
            </div>

            {sorted.length === 0 ? (
                <div className="empty-state">
                    <span>// waiting for sensor data</span>
                </div>
            ) : (
                <div style={{ overflowX: "auto", overflowY: "auto", flex: 1, minHeight: 0 }}>
                    <table className="data-table">
                        <thead style={{ position: "sticky", top: 0, zIndex: 1, background: "var(--s2)" }}>
                            <tr>
                                {["ENDPOINT", "TRAFFIC", "MEAN", "PH SCORE", "STATUS", "OBS"].map(h => (
                                    <th key={h}>{h}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {sorted.map(stat => {
                                const isSelected = selectedEndpoint === stat.endpoint;
                                const isZombie   = stat.ph_score > PH_ALARM;
                                const isDormant  = stat.dormant;
                                const status = getStatus(stat);
                                const rowClass = isSelected ? "row--selected" : isZombie ? "row--danger" : isDormant ? "row--warn" : "";
                                return (
                                    <tr
                                        key={stat.endpoint}
                                        className={rowClass}
                                        onClick={() => onSelectEndpoint(stat.endpoint)}
                                        title="Click to highlight in network graph"
                                        style={{ cursor: "pointer" }}
                                    >
                                        <td
                                            title={stat.endpoint}
                                            style={{
                                                fontFamily: "var(--mono)",
                                                fontSize: "11px",
                                                maxWidth: 240,
                                                overflow: "hidden",
                                                textOverflow: "ellipsis",
                                                whiteSpace: "nowrap",
                                                color: "var(--t1)",
                                                fontWeight: isSelected ? 700 : 400,
                                            }}
                                        >
                                            {stat.endpoint}
                                        </td>
                                        <td style={{ fontFamily: "var(--mono)", fontSize: "12px", textAlign: "center", color: "var(--t2)" }}>
                                            {stat.current_window}
                                        </td>
                                        <td style={{ fontFamily: "var(--mono)", fontSize: "12px", color: "var(--t2)" }}>
                                            {stat.running_mean.toFixed(2)}
                                        </td>
                                        <td style={{ minWidth: 140 }}>
                                            <PhBar score={stat.ph_score} />
                                        </td>
                                        <td>
                                            <span className={`badge ${status.badgeClass}`}>{status.label}</span>
                                        </td>
                                        <td style={{ fontFamily: "var(--mono)", fontSize: "12px", color: "var(--t3)" }}>
                                            {stat.total_observations}
                                            {stat.dormant && stat.dormant_windows > 0 && (
                                                <span style={{ marginLeft: 4, fontSize: "10px", color: "var(--orange)" }}>
                                                    ({stat.dormant_windows}w)
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
