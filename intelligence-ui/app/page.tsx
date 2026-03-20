"use client";

import { useEffect, useState } from "react";

interface EndpointStats {
    endpoint: string;
    current_window: number;
    running_mean: number;
    ph_score: number;
    dormant: boolean;
    dormant_windows: number;
    total_observations: number;
}

// Fetch drift stats from the eBPF sensor metrics server.
// The sensor runs on host network at port 9090; when accessed from a browser
// pointed at localhost this resolves correctly in development.
// In production behind KrakenD, configure a /drift/stats proxy route.
const DRIFT_STATS_URL =
    (typeof window !== "undefined" &&
        (window as unknown as { __DRIFT_URL__?: string }).__DRIFT_URL__) ||
    "http://localhost:9090/drift/stats";

export default function DashboardPage() {
    const [driftStats, setDriftStats] = useState<EndpointStats[]>([]);
    const [driftError, setDriftError] = useState<string | null>(null);

    useEffect(() => {
        let cancelled = false;

        async function fetchDrift() {
            try {
                const res = await fetch(DRIFT_STATS_URL);
                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`);
                }
                const data: EndpointStats[] = await res.json();
                if (!cancelled) setDriftStats(data);
            } catch (err) {
                if (!cancelled) setDriftError(String(err));
            }
        }

        fetchDrift();
        const interval = setInterval(fetchDrift, 10_000); // refresh every 10s
        return () => {
            cancelled = true;
            clearInterval(interval);
        };
    }, []);

    const zombieCount = driftStats.filter(
        (s) => !s.dormant && s.ph_score > 0
    ).length;
    const dormantCount = driftStats.filter((s) => s.dormant).length;

    return (
        <main style={{ padding: "2rem" }}>
            <header style={{ marginBottom: "2rem" }}>
                <h1 style={{ fontSize: "1.5rem", fontWeight: 700, color: "var(--color-accent)" }}>
                    AuralisAPI
                </h1>
                <p style={{ color: "var(--color-text-muted)", fontFamily: "var(--font-mono)" }}>
                    Autonomous Zero-Trust Perimeter · Intelligence Dashboard
                </p>
            </header>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "1rem", marginBottom: "2rem" }}>
                {[
                    { label: "Total Endpoints", value: driftStats.length || "—", color: "var(--color-info)" },
                    { label: "Zombie APIs", value: zombieCount || "—", color: "var(--color-danger)" },
                    { label: "Dormant Endpoints", value: dormantCount || "—", color: "var(--color-warning)" },
                    { label: "Quarantined", value: "—", color: "var(--color-ok)" },
                ].map((stat) => (
                    <div key={stat.label} className="card">
                        <p style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                            {stat.label}
                        </p>
                        <p style={{ fontSize: "2rem", fontWeight: 700, color: stat.color, fontFamily: "var(--font-mono)" }}>
                            {stat.value}
                        </p>
                    </div>
                ))}
            </div>

            <div className="card" style={{ marginBottom: "2rem" }}>
                <h2 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "1rem" }}>
                    Endpoint Drift Monitor
                    <span style={{ fontSize: "0.75rem", fontWeight: 400, color: "var(--color-text-muted)", marginLeft: "0.5rem" }}>
                        Page-Hinkley change-point detection · refreshes every 10s
                    </span>
                </h2>

                {driftError && (
                    <p style={{ color: "var(--color-danger)", fontFamily: "var(--font-mono)", fontSize: "0.875rem" }}>
                        Drift stats unavailable: {driftError}
                    </p>
                )}

                {!driftError && driftStats.length === 0 && (
                    <p style={{ color: "var(--color-text-muted)", fontFamily: "var(--font-mono)", fontSize: "0.875rem" }}>
                        Waiting for sensor data…
                    </p>
                )}

                {driftStats.length > 0 && (
                    <div style={{ overflowX: "auto" }}>
                        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.875rem", fontFamily: "var(--font-mono)" }}>
                            <thead>
                                <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                                    {["Endpoint", "Window Reqs", "Mean", "PH Score", "Dormant", "Total Obs"].map((h) => (
                                        <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.75rem", color: "var(--color-text-muted)", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                                            {h}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {driftStats.map((s) => (
                                    <tr
                                        key={s.endpoint}
                                        style={{
                                            borderBottom: "1px solid var(--color-border)",
                                            background: s.dormant
                                                ? "rgba(249, 115, 22, 0.08)"
                                                : s.ph_score > 25
                                                    ? "rgba(239, 68, 68, 0.08)"
                                                    : "transparent",
                                        }}
                                    >
                                        <td style={{ padding: "0.5rem 0.75rem", color: "var(--color-accent)" }}>{s.endpoint}</td>
                                        <td style={{ padding: "0.5rem 0.75rem" }}>{s.current_window}</td>
                                        <td style={{ padding: "0.5rem 0.75rem" }}>{s.running_mean.toFixed(3)}</td>
                                        <td style={{
                                            padding: "0.5rem 0.75rem",
                                            color: s.ph_score > 25 ? "var(--color-danger)" : "inherit",
                                            fontWeight: s.ph_score > 25 ? 700 : 400,
                                        }}>
                                            {s.ph_score.toFixed(3)}
                                        </td>
                                        <td style={{ padding: "0.5rem 0.75rem", color: s.dormant ? "var(--color-warning)" : "inherit" }}>
                                            {s.dormant ? `Yes (${s.dormant_windows}w)` : "No"}
                                        </td>
                                        <td style={{ padding: "0.5rem 0.75rem" }}>{s.total_observations}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            <div className="card">
                <h2 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "1rem" }}>API Dependency Graph</h2>
                <p style={{ color: "var(--color-text-muted)", fontFamily: "var(--font-mono)", fontSize: "0.875rem" }}>
                    D3.js graph will render here in Phase 2 — connecting to{" "}
                    <code style={{ color: "var(--color-accent)" }}>GET /api/inventory</code>
                </p>
            </div>
        </main>
    );
}
