"use client";

import { useEffect, useState, useMemo, useCallback, useRef } from "react";
import dynamic from "next/dynamic";
import { GraphNode, GraphEdge } from "./components/NetworkGraph";
import { Incident } from "./components/IncidentPanel";
import { EndpointStats } from "./components/DriftTable";
import { HoneypotEvent } from "./components/HoneypotFeed";

// Dynamic import to prevent SSR issues with D3/ResizeObserver
const NetworkGraph = dynamic(() => import("./components/NetworkGraph"), { ssr: false });
const IncidentPanel = dynamic(() => import("./components/IncidentPanel"), { ssr: false });
const DriftTable = dynamic(() => import("./components/DriftTable"), { ssr: false });
const HoneypotFeed = dynamic(() => import("./components/HoneypotFeed"), { ssr: false });

// ── Types ─────────────────────────────────────────────────────────────────────

interface InventoryEndpoint {
    path: string;
    classification: string | null;
    severity: string | null;
    is_pii_exposed: boolean;
}

interface InventoryResponse {
    endpoints: InventoryEndpoint[];
    total: number;
    zombies: number;
    shadows: number;
}

interface GatewayConfig {
    quarantined: string[];
    active: string[];
    quarantined_count: number;
    active_count: number;
    parse_ok: boolean;
    error: string | null;
}

interface HoneypotEventsResponse {
    events: HoneypotEvent[];
    total: number;
}

interface IncidentsResponse {
    incidents: Incident[];
    total: number;
}

// Service health state
type ServiceStatus = "ok" | "error" | "loading";

interface ServiceHealth {
    brain: ServiceStatus;
    sensor: ServiceStatus;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const DRIFT_STATS_URL = "/drift/stats";  // proxied through Next.js → sensor :9090
const POLL_INTERVAL_MS = 5_000;

// ── Helpers ───────────────────────────────────────────────────────────────────

async function safeFetch<T>(url: string, init?: RequestInit): Promise<T | null> {
    try {
        const res = await fetch(url, { ...init, signal: AbortSignal.timeout(4000) });
        if (!res.ok) return null;
        return (await res.json()) as T;
    } catch {
        return null;
    }
}

function useClock(): string {
    const [time, setTime] = useState<string>("");
    useEffect(() => {
        function tick() {
            setTime(new Date().toLocaleTimeString("en-US", {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false,
            }));
        }
        tick();
        const id = setInterval(tick, 1000);
        return () => clearInterval(id);
    }, []);
    return time;
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function DashboardPage() {
    const [driftStats, setDriftStats] = useState<EndpointStats[]>([]);
    const [incidents, setIncidents] = useState<Incident[]>([]);
    const [inventory, setInventory] = useState<InventoryResponse>({
        endpoints: [], total: 0, zombies: 0, shadows: 0,
    });
    const [gatewayConfig, setGatewayConfig] = useState<GatewayConfig | null>(null);
    const [honeypotEvents, setHoneypotEvents] = useState<HoneypotEvent[]>([]);
    const [honeypotTotal, setHoneypotTotal] = useState<number>(0);
    const [selectedEndpoint, setSelectedEndpoint] = useState<string | null>(null);
    const [loadingIncidentId, setLoadingIncidentId] = useState<string | null>(null);
    const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
    const [serviceHealth, setServiceHealth] = useState<ServiceHealth>({
        brain: "loading",
        sensor: "loading",
    });

    const clock = useClock();
    const isMounted = useRef(true);
    useEffect(() => {
        isMounted.current = true;
        return () => { isMounted.current = false; };
    }, []);

    // ── Data fetching ────────────────────────────────────────────────────────

    const fetchAllData = useCallback(async () => {
        // Parallel fetch all data sources
        const [driftResult, incidentsResult, inventoryResult, gatewayResult, honeypotResult] =
            await Promise.all([
                safeFetch<EndpointStats[]>(DRIFT_STATS_URL),
                safeFetch<IncidentsResponse>("/brain/incidents"),
                safeFetch<InventoryResponse>("/brain/inventory"),
                safeFetch<GatewayConfig>("/brain/gateway/config"),
                safeFetch<HoneypotEventsResponse>("/brain/honeypot/events"),
            ]);

        if (!isMounted.current) return;

        // Update service health
        setServiceHealth({
            brain: incidentsResult !== null ? "ok" : "error",
            sensor: driftResult !== null ? "ok" : "error",
        });

        if (driftResult) setDriftStats(driftResult);
        if (incidentsResult?.incidents) setIncidents(incidentsResult.incidents);
        if (inventoryResult) setInventory(inventoryResult);
        if (gatewayResult) setGatewayConfig(gatewayResult);
        if (honeypotResult) {
            setHoneypotEvents(honeypotResult.events ?? []);
            setHoneypotTotal(honeypotResult.total ?? 0);
        }

        setLastUpdated(new Date());
    }, []);

    useEffect(() => {
        fetchAllData();
        const interval = setInterval(fetchAllData, POLL_INTERVAL_MS);
        return () => clearInterval(interval);
    }, [fetchAllData]);

    // ── Graph data derivation ─────────────────────────────────────────────────

    const graphNodes: GraphNode[] = useMemo(() => {
        const nodeMap = new Map<string, GraphNode>();

        // Gateway node always present
        nodeMap.set("gateway", {
            id: "gateway",
            label: "API Gateway",
            type: "gateway",
            classification: null,
            severity: null,
            is_pii: false,
            ph_score: 0,
            dormant: false,
            traffic: 0,
        });

        // Add nodes from inventory
        inventory.endpoints.forEach((ep) => {
            if (!ep.path || ep.path === "unknown") return;
            const existing = nodeMap.get(ep.path);
            if (!existing) {
                nodeMap.set(ep.path, {
                    id: ep.path,
                    label: ep.path,
                    type: "endpoint",
                    classification: ep.classification,
                    severity: ep.severity,
                    is_pii: ep.is_pii_exposed,
                    ph_score: 0,
                    dormant: false,
                    traffic: 0,
                });
            }
        });

        // Overlay drift stats — update ph_score, dormant, traffic
        driftStats.forEach((stat) => {
            const existing = nodeMap.get(stat.endpoint);
            if (existing) {
                existing.ph_score = stat.ph_score;
                existing.dormant = stat.dormant;
                existing.traffic = stat.current_window;
                // Infer classification from drift if not set by inventory
                if (!existing.classification || existing.classification === "unknown") {
                    if (stat.ph_score > 25 && !stat.dormant) {
                        existing.classification = "active_zombie";
                        existing.severity = existing.severity ?? "high";
                    } else if (stat.dormant) {
                        existing.classification = "dormant_zombie";
                    }
                }
            } else {
                // Drift-only endpoint (not yet in inventory)
                let classification: string | null = null;
                let severity: string | null = null;
                if (stat.ph_score > 25 && !stat.dormant) {
                    classification = "active_zombie";
                    severity = "high";
                } else if (stat.dormant) {
                    classification = "dormant_zombie";
                }
                nodeMap.set(stat.endpoint, {
                    id: stat.endpoint,
                    label: stat.endpoint,
                    type: "endpoint",
                    classification,
                    severity,
                    is_pii: false,
                    ph_score: stat.ph_score,
                    dormant: stat.dormant,
                    traffic: stat.current_window,
                });
            }
        });

        return Array.from(nodeMap.values());
    }, [inventory, driftStats]);

    const graphEdges: GraphEdge[] = useMemo(() => {
        return graphNodes
            .filter((n) => n.type === "endpoint")
            .map((n) => ({ source: "gateway", target: n.id }));
    }, [graphNodes]);

    // ── Approve / Reject handlers ─────────────────────────────────────────────

    const handleApprove = useCallback(async (threadId: string) => {
        setLoadingIncidentId(threadId);
        try {
            await fetch(`/brain/incidents/${threadId}/approve`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: "{}",
            });
            // Re-fetch incidents after action
            const result = await safeFetch<IncidentsResponse>("/brain/incidents");
            if (result?.incidents && isMounted.current) {
                setIncidents(result.incidents);
            }
        } catch {
            // Silently ignore — UI will re-sync on next poll
        } finally {
            if (isMounted.current) setLoadingIncidentId(null);
        }
    }, []);

    const handleReject = useCallback(async (threadId: string) => {
        setLoadingIncidentId(threadId);
        try {
            await fetch(`/brain/incidents/${threadId}/reject`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: "{}",
            });
            const result = await safeFetch<IncidentsResponse>("/brain/incidents");
            if (result?.incidents && isMounted.current) {
                setIncidents(result.incidents);
            }
        } catch {
            // Silently ignore
        } finally {
            if (isMounted.current) setLoadingIncidentId(null);
        }
    }, []);

    // ── Node click handler ────────────────────────────────────────────────────

    const handleNodeClick = useCallback((node: GraphNode) => {
        if (node.type === "gateway") return;
        setSelectedEndpoint((prev) => prev === node.id ? null : node.id);
    }, []);

    const handleSelectEndpoint = useCallback((endpoint: string) => {
        setSelectedEndpoint((prev) => prev === endpoint ? null : endpoint);
    }, []);

    // ── Derived stats ─────────────────────────────────────────────────────────

    const activeZombieCount = useMemo(
        () => inventory.endpoints.filter((e) => e.classification === "active_zombie").length,
        [inventory]
    );

    const quarantinedCount = gatewayConfig?.quarantined_count ?? 0;

    const statCards = [
        {
            label: "Total Endpoints",
            value: inventory.total || graphNodes.filter(n => n.type === "endpoint").length || "—",
            sub: "tracked APIs",
            accent: "var(--color-info)",
        },
        {
            label: "Active Zombies",
            value: activeZombieCount || "—",
            sub: "flagged by AI brain",
            accent: "var(--color-danger)",
        },
        {
            label: "Quarantined",
            value: quarantinedCount || "—",
            sub: "returning 410 Gone",
            accent: "var(--color-ok)",
        },
        {
            label: "Honeypot Hits",
            value: honeypotTotal || "—",
            sub: "attacker probes",
            accent: "var(--color-warning)",
        },
    ];

    // ── Render ────────────────────────────────────────────────────────────────

    return (
        <>
            {/* ── Header ─────────────────────────────────────────────────── */}
            <header className="app-header">
                <div className="app-header__logo">
                    <svg
                        width="22"
                        height="22"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="var(--color-accent)"
                        strokeWidth={2}
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        aria-hidden="true"
                    >
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        <path d="M9 12l2 2 4-4" />
                    </svg>
                    <span className="app-header__logo-text">AuralisAPI</span>
                    <span className="app-header__logo-sub">
                        · Zero-Trust API Intelligence
                    </span>
                </div>

                <div className="app-header__divider" />

                <div className="app-header__services">
                    <div className="service-dot">
                        <div
                            className={`service-dot__indicator service-dot__indicator--${serviceHealth.brain}`}
                        />
                        <span>brain</span>
                    </div>
                    <div className="service-dot">
                        <div
                            className={`service-dot__indicator service-dot__indicator--${serviceHealth.sensor}`}
                        />
                        <span>sensor</span>
                    </div>
                </div>

                <div className="app-header__right">
                    <span className="app-header__timestamp">
                        updated {lastUpdated.toLocaleTimeString("en-US", {
                            hour: "2-digit",
                            minute: "2-digit",
                            second: "2-digit",
                            hour12: false,
                        })}
                    </span>
                    <span className="app-header__clock">{clock}</span>
                </div>
            </header>

            {/* ── Dashboard Content ───────────────────────────────────────── */}
            <div className="dashboard-content">

                {/* ── Stats Row ──────────────────────────────────────────── */}
                <div className="stats-row">
                    {statCards.map((card) => (
                        <div
                            key={card.label}
                            className="stat-card"
                            // @ts-ignore — CSS custom property
                            style={{ "--stat-accent": card.accent } as React.CSSProperties}
                        >
                            <p className="stat-card__label">{card.label}</p>
                            <p className="stat-card__value">{card.value}</p>
                            <p className="stat-card__sub">{card.sub}</p>
                        </div>
                    ))}
                </div>

                {/* ── Main Grid: Graph + Incidents ──────────────────────── */}
                <div className="main-grid">
                    {/* Graph Panel */}
                    <div className="card graph-panel">
                        <div className="graph-panel__header">
                            <span className="graph-panel__title">
                                API Dependency Graph
                            </span>
                            <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                                {selectedEndpoint && (
                                    <span
                                        style={{
                                            fontSize: "0.7rem",
                                            color: "var(--color-accent)",
                                            fontFamily: "var(--font-mono)",
                                            maxWidth: 200,
                                            overflow: "hidden",
                                            textOverflow: "ellipsis",
                                            whiteSpace: "nowrap",
                                        }}
                                        title={selectedEndpoint}
                                    >
                                        {selectedEndpoint}
                                    </span>
                                )}
                                {selectedEndpoint && (
                                    <button
                                        onClick={() => setSelectedEndpoint(null)}
                                        style={{
                                            background: "none",
                                            border: "none",
                                            cursor: "pointer",
                                            color: "var(--color-text-muted)",
                                            padding: "2px 4px",
                                            fontSize: "0.7rem",
                                            borderRadius: "var(--radius-sm)",
                                        }}
                                        title="Clear selection"
                                    >
                                        ✕
                                    </button>
                                )}
                                <span
                                    className="panel-header__count"
                                    style={{ fontSize: "0.65rem" }}
                                >
                                    {graphNodes.filter(n => n.type === "endpoint").length} endpoints
                                </span>
                            </div>
                        </div>
                        <div className="graph-panel__body">
                            <NetworkGraph
                                nodes={graphNodes}
                                edges={graphEdges}
                                onNodeClick={handleNodeClick}
                                selectedNodeId={selectedEndpoint}
                            />
                        </div>
                    </div>

                    {/* Incidents Panel */}
                    <IncidentPanel
                        incidents={incidents}
                        onApprove={handleApprove}
                        onReject={handleReject}
                        loadingId={loadingIncidentId}
                        selectedEndpoint={selectedEndpoint}
                    />
                </div>

                {/* ── Bottom Grid: Drift + Honeypot ─────────────────────── */}
                <div className="bottom-grid">
                    <div className="card drift-panel">
                        <DriftTable
                            stats={driftStats}
                            onSelectEndpoint={handleSelectEndpoint}
                            selectedEndpoint={selectedEndpoint}
                        />
                    </div>

                    <div className="card honeypot-panel">
                        <HoneypotFeed events={honeypotEvents} />
                    </div>
                </div>

            </div>
        </>
    );
}
