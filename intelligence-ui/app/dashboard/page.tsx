"use client";

import { useEffect, useState, useMemo, useCallback, useRef, Suspense } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { GraphNode, GraphEdge } from "../components/NetworkGraph";
import { Incident } from "../components/IncidentPanel";
import { EndpointStats } from "../components/DriftTable";
import { HoneypotEvent } from "../components/HoneypotFeed";

// Dynamic imports — prevents SSR issues with D3/ResizeObserver
const NetworkGraph        = dynamic(() => import("../components/NetworkGraph"),        { ssr: false });
const IncidentPanel       = dynamic(() => import("../components/IncidentPanel"),       { ssr: false });
const DriftTable          = dynamic(() => import("../components/DriftTable"),          { ssr: false });
const HoneypotFeed        = dynamic(() => import("../components/HoneypotFeed"),        { ssr: false });
const IncidentDetailPanel = dynamic(() => import("../components/IncidentDetailPanel"), { ssr: false });

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
type ServiceStatus = "ok" | "error" | "loading";
interface ServiceHealth {
    brain: ServiceStatus;
    sensor: ServiceStatus;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function getBrainToken(): string | null {
    if (typeof window === "undefined") return null;
    return localStorage.getItem("auralis_brain_token");
}

function getBrainHeaders(): Record<string, string> {
    const token = getBrainToken();
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (token) h["Authorization"] = `Bearer ${token}`;
    return h;
}

async function safeFetch<T>(url: string): Promise<T | null> {
    try {
        const headers: Record<string, string> = {};
        const token = getBrainToken();
        if (token && url.startsWith("/brain")) headers["Authorization"] = `Bearer ${token}`;
        const res = await fetch(url, { signal: AbortSignal.timeout(4000), headers });
        if (res.status === 401) {
            localStorage.removeItem("auralis_auth");
            localStorage.removeItem("auralis_brain_token");
            window.location.href = "/login";
            return null;
        }
        if (!res.ok) return null;
        return (await res.json()) as T;
    } catch { return null; }
}

function formatSecsAgo(secs: number): string {
    if (secs < 60) return `${secs}s ago`;
    return `${Math.floor(secs / 60)}m ${secs % 60}s ago`;
}

function useClock(): string {
    const [time, setTime] = useState("");
    useEffect(() => {
        const tick = () => setTime(new Date().toLocaleTimeString("en-US", {
            hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
        }));
        tick();
        const id = setInterval(tick, 1000);
        return () => clearInterval(id);
    }, []);
    return time;
}

function svcColor(s: ServiceStatus): string {
    return s === "ok" ? "var(--green)" : s === "error" ? "var(--red)" : "var(--t3)";
}

// ── Dashboard inner component ─────────────────────────────────────────────────
function DashboardInner({ initialIncidentId }: { initialIncidentId: string | null }) {
    const router    = useRouter();
    const clock     = useClock();
    const isMounted = useRef(true);

    useEffect(() => {
        isMounted.current = true;
        return () => { isMounted.current = false; };
    }, []);

    // ── State ────────────────────────────────────────────────────────────────
    const [driftStats,       setDriftStats]       = useState<EndpointStats[]>([]);
    const [incidents,        setIncidents]        = useState<Incident[]>([]);
    const [inventory,        setInventory]        = useState<InventoryResponse>({ endpoints: [], total: 0, zombies: 0, shadows: 0 });
    const [gatewayConfig,    setGatewayConfig]    = useState<GatewayConfig | null>(null);
    const [honeypotEvents,   setHoneypotEvents]   = useState<HoneypotEvent[]>([]);
    const [honeypotTotal,    setHoneypotTotal]    = useState(0);
    const [selectedEndpoint, setSelectedEndpoint] = useState<string | null>(null);
    const [loadingId,        setLoadingId]        = useState<string | null>(null);
    const [actionError,      setActionError]      = useState<string | null>(null);
    const [actionSuccess,    setActionSuccess]    = useState<string | null>(null);
    const [serviceHealth,    setServiceHealth]    = useState<ServiceHealth>({ brain: "loading", sensor: "loading" });
    const [detailThreadId,   setDetailThreadId]   = useState<string | null>(initialIncidentId);

    // 5.1 — error states
    const [fetchError,       setFetchError]       = useState(false);
    const [lastSuccessTime,  setLastSuccessTime]  = useState<Date | null>(null);
    const [secsAgo,          setSecsAgo]          = useState<number | null>(null);

    // 5.2 — initial load skeleton
    const [initialLoad,      setInitialLoad]      = useState(true);

    useEffect(() => {
        if (initialIncidentId) setDetailThreadId(initialIncidentId);
    }, [initialIncidentId]);

    // ── Seconds-ago ticker (5.1) ─────────────────────────────────────────────
    useEffect(() => {
        if (!lastSuccessTime) return;
        const tick = () => setSecsAgo(Math.floor((Date.now() - lastSuccessTime.getTime()) / 1000));
        tick();
        const id = setInterval(tick, 1000);
        return () => clearInterval(id);
    }, [lastSuccessTime]);

    const handleViewDetail  = useCallback((id: string) => setDetailThreadId(id), []);
    const handleCloseDetail = useCallback(() => setDetailThreadId(null), []);

    function handleLogout() {
        localStorage.removeItem("auralis_auth");
        router.replace("/login");
    }

    // ── Polling ──────────────────────────────────────────────────────────────
    const fetchAll = useCallback(async () => {
        const [drift, inc, inv, gw, hp] = await Promise.all([
            safeFetch<EndpointStats[]>("/drift/stats"),
            safeFetch<IncidentsResponse>("/brain/incidents"),
            safeFetch<InventoryResponse>("/brain/inventory"),
            safeFetch<GatewayConfig>("/brain/gateway/config"),
            safeFetch<HoneypotEventsResponse>("/brain/honeypot/events"),
        ]);
        if (!isMounted.current) return;

        const anyOk = inc !== null || drift !== null || inv !== null;
        const allFailed = !inc && !drift && !inv && !gw && !hp;

        setFetchError(allFailed);
        if (anyOk) {
            setLastSuccessTime(new Date());
            setInitialLoad(false);
        }

        setServiceHealth({
            brain:  inc   !== null ? "ok" : "error",
            sensor: drift !== null ? "ok" : "error",
        });
        if (drift) setDriftStats(drift);
        if (inc?.incidents) setIncidents(inc.incidents);
        if (inv) setInventory(inv);
        if (gw)  setGatewayConfig(gw);
        if (hp)  { setHoneypotEvents(hp.events ?? []); setHoneypotTotal(hp.total ?? 0); }
    }, []);

    useEffect(() => {
        fetchAll();
        const id = setInterval(fetchAll, 5000);
        return () => clearInterval(id);
    }, [fetchAll]);

    // ── Graph data ───────────────────────────────────────────────────────────
    const graphNodes: GraphNode[] = useMemo(() => {
        const map = new Map<string, GraphNode>();
        map.set("gateway", {
            id: "gateway", label: "API Gateway", type: "gateway",
            classification: null, severity: null,
            is_pii: false, ph_score: 0, dormant: false, traffic: 0,
        });
        inventory.endpoints.forEach(ep => {
            if (!ep.path || ep.path === "unknown") return;
            if (!map.has(ep.path)) {
                map.set(ep.path, {
                    id: ep.path, label: ep.path, type: "endpoint",
                    classification: ep.classification, severity: ep.severity,
                    is_pii: ep.is_pii_exposed, ph_score: 0, dormant: false, traffic: 0,
                });
            }
        });
        driftStats.forEach(stat => {
            const node = map.get(stat.endpoint);
            if (node) {
                node.ph_score = stat.ph_score;
                node.dormant  = stat.dormant;
                node.traffic  = stat.current_window;
                if (!node.classification || node.classification === "unknown") {
                    if      (stat.ph_score > 25 && !stat.dormant) { node.classification = "active_zombie"; node.severity = node.severity ?? "high"; }
                    else if (stat.dormant)                         { node.classification = "dormant_zombie"; }
                    else if (stat.ph_score >= 10 && !stat.dormant){ node.classification = "drifting"; }
                }
            } else {
                let cls: string | null = null, sev: string | null = null;
                if      (stat.ph_score > 25 && !stat.dormant) { cls = "active_zombie"; sev = "high"; }
                else if (stat.dormant)                         { cls = "dormant_zombie"; }
                else if (stat.ph_score >= 10 && !stat.dormant){ cls = "drifting"; }
                map.set(stat.endpoint, {
                    id: stat.endpoint, label: stat.endpoint, type: "endpoint",
                    classification: cls, severity: sev,
                    is_pii: false, ph_score: stat.ph_score, dormant: stat.dormant, traffic: stat.current_window,
                });
            }
        });
        return Array.from(map.values());
    }, [inventory, driftStats]);

    const graphEdges: GraphEdge[] = useMemo(() =>
        graphNodes.filter(n => n.type === "endpoint").map(n => ({ source: "gateway", target: n.id })),
        [graphNodes]
    );

    // ── Actions (5.4 — optimistic update + notes) ─────────────────────────────
    const handleApprove = useCallback(async (threadId: string, notes?: string) => {
        if (!isMounted.current) return;
        // Optimistic: hide the awaiting indicator immediately
        setIncidents(prev => prev.map(i =>
            i.thread_id === threadId ? { ...i, status: "approved" } : i
        ));
        setLoadingId(threadId);
        setActionError(null);
        setActionSuccess(null);
        try {
            const res = await fetch(`/brain/incidents/${threadId}/approve`, {
                method: "POST",
                headers: getBrainHeaders(),
                body: JSON.stringify({ notes: notes ?? "" }),
            });
            if (!res.ok) {
                let detail = `HTTP ${res.status}`;
                try { const j = await res.json(); detail = j.detail ?? j.message ?? detail; } catch {}
                throw new Error(`Approve failed: ${detail}`);
            }
            if (isMounted.current) {
                setActionSuccess("Incident approved — KrakenD enforcement triggered.");
                setTimeout(() => { if (isMounted.current) setActionSuccess(null); }, 5000);
            }
        } catch (err: unknown) {
            // Revert optimistic update on failure
            if (isMounted.current) {
                setIncidents(prev => prev.map(i =>
                    i.thread_id === threadId ? { ...i, status: "awaiting_approval" } : i
                ));
                setActionError(err instanceof Error ? err.message : "Approve failed — check brain logs");
            }
        } finally {
            if (isMounted.current) setLoadingId(null);
            setTimeout(async () => {
                const r = await safeFetch<IncidentsResponse>("/brain/incidents");
                if (r?.incidents && isMounted.current) setIncidents(r.incidents);
            }, 1000);
        }
    }, []);

    const handleReject = useCallback(async (threadId: string, notes?: string) => {
        if (!isMounted.current) return;
        setIncidents(prev => prev.map(i =>
            i.thread_id === threadId ? { ...i, status: "rejected" } : i
        ));
        setLoadingId(threadId);
        setActionError(null);
        setActionSuccess(null);
        try {
            const res = await fetch(`/brain/incidents/${threadId}/reject`, {
                method: "POST",
                headers: getBrainHeaders(),
                body: JSON.stringify({ notes: notes ?? "" }),
            });
            if (!res.ok) {
                let detail = `HTTP ${res.status}`;
                try { const j = await res.json(); detail = j.detail ?? j.message ?? detail; } catch {}
                throw new Error(`Reject failed: ${detail}`);
            }
            if (isMounted.current) {
                setActionSuccess("Incident rejected — report generated, no gateway changes.");
                setTimeout(() => { if (isMounted.current) setActionSuccess(null); }, 5000);
            }
        } catch (err: unknown) {
            if (isMounted.current) {
                setIncidents(prev => prev.map(i =>
                    i.thread_id === threadId ? { ...i, status: "awaiting_approval" } : i
                ));
                setActionError(err instanceof Error ? err.message : "Reject failed — check brain logs");
            }
        } finally {
            if (isMounted.current) setLoadingId(null);
            setTimeout(async () => {
                const r = await safeFetch<IncidentsResponse>("/brain/incidents");
                if (r?.incidents && isMounted.current) setIncidents(r.incidents);
            }, 1000);
        }
    }, []);

    const handleNodeClick      = useCallback((node: GraphNode) => {
        if (node.type === "gateway") return;
        setSelectedEndpoint(prev => prev === node.id ? null : node.id);
    }, []);
    const handleSelectEndpoint = useCallback((ep: string) => {
        setSelectedEndpoint(prev => prev === ep ? null : ep);
    }, []);

    // ── Derived ──────────────────────────────────────────────────────────────
    const activeZombies = useMemo(() =>
        Math.max(
            inventory.endpoints.filter(e => e.classification === "active_zombie").length,
            driftStats.filter(s => s.ph_score > 25 && !s.dormant).length,
        ), [inventory, driftStats]);
    const quarantined   = gatewayConfig?.quarantined_count ?? 0;
    const endpointCount = inventory.total || graphNodes.filter(n => n.type === "endpoint").length;
    const awaitingCount = incidents.filter(i => i.status === "awaiting_approval").length;

    // ── Render ────────────────────────────────────────────────────────────────
    return (
        <div style={{ minHeight: "100vh", background: "var(--bg)", fontFamily: "var(--mono)", paddingBottom: 40 }}>

            {/* ── Header ──────────────────────────────────────────────────── */}
            <header style={{
                position: "sticky", top: 0, zIndex: 50,
                background: "#0c0c0c",
                borderBottom: "1px solid #1e1e1e",
                padding: "0 16px",
                height: 52,
                display: "flex", alignItems: "center", gap: "12px",
                flexWrap: "nowrap", overflow: "hidden",
            }}>
                <Link href="/" style={{ textDecoration: "none", flexShrink: 0 }}>
                    <span style={{ fontFamily: "var(--sans)", fontSize: "16px", fontWeight: 800, color: "#b8ff00", letterSpacing: "-0.01em" }}>AURALIS</span>
                </Link>
                <span style={{ color: "#2a2a2a", fontSize: "14px" }}>/</span>
                <span style={{ fontSize: "11px", color: "#555", textTransform: "uppercase", letterSpacing: "0.08em" }}>dashboard</span>

                <div style={{ width: "1px", height: "18px", background: "#1e1e1e", margin: "0 4px" }} />

                {/* Service health */}
                <div style={{ display: "flex", gap: "14px" }}>
                    {(["sensor", "brain"] as const).map(svc => (
                        <span key={svc} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: "10px", fontFamily: "var(--mono)", fontWeight: 700, letterSpacing: "0.06em",
                            color: svcColor(serviceHealth[svc]) }}>
                            <span style={{ width: 6, height: 6, borderRadius: "50%", display: "inline-block",
                                background: svcColor(serviceHealth[svc]),
                                animation: serviceHealth[svc] === "ok" ? "pulse-ok 2s infinite" : undefined }} />
                            {svc.toUpperCase()}
                        </span>
                    ))}
                </div>

                {/* 5.1 — Reconnecting badge */}
                {fetchError && (
                    <span className="reconnect-badge">⚠ Reconnecting…</span>
                )}

                {awaitingCount > 0 && (
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: "3px 10px", background: "rgba(255,149,0,0.1)", border: "1px solid #ff9500", color: "#ff9500", fontSize: "10px", fontWeight: 700, letterSpacing: "0.08em", animation: "pulse-ok 2s infinite", flexShrink: 0 }}>
                        ⚡ {awaitingCount} AWAITING
                    </span>
                )}

                <div style={{ flex: 1 }} />

                {/* Last updated display */}
                {secsAgo !== null && (
                    <span style={{ fontSize: "10px", color: fetchError ? "var(--orange)" : "#444", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>
                        {fetchError ? `⚠ ${formatSecsAgo(secsAgo)}` : (
                            <>
                                <span style={{ width: 5, height: 5, background: "#22c55e", display: "inline-block", borderRadius: "50%", animation: "pulse-ok 3s infinite", marginRight: 4 }} />
                                {formatSecsAgo(secsAgo)}
                            </>
                        )}
                    </span>
                )}

                <span style={{ fontSize: "11px", color: "#444", fontFamily: "var(--mono)", letterSpacing: "0.04em" }}>{clock}</span>

                <div style={{ width: "1px", height: "18px", background: "#1e1e1e" }} />

                {/* Extra nav items hidden on mobile via .dash-nav-extra */}
                <div className="dash-nav-extra" style={{ display: "flex", gap: 8 }}>
                    <Link href="/dashboard/attack-arena" style={{ textDecoration: "none" }}>
                        <button style={{ background: "rgba(255,45,120,0.08)", border: "1px solid #ff2d78", color: "#ff2d78", fontFamily: "var(--mono)", fontSize: "11px", padding: "5px 12px", cursor: "pointer", letterSpacing: "0.06em", transition: "background 0.12s" }}
                            onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(255,45,120,0.15)"; }}
                            onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(255,45,120,0.08)"; }}
                        >◈ ATTACK ARENA</button>
                    </Link>
                    <button onClick={handleLogout} style={{ background: "transparent", border: "1px solid #222", color: "#555", fontFamily: "var(--mono)", fontSize: "11px", padding: "5px 12px", cursor: "pointer", transition: "color 0.12s, border-color 0.12s" }}
                        onMouseEnter={e => { const b = e.currentTarget as HTMLButtonElement; b.style.color = "#f0f0f0"; b.style.borderColor = "#444"; }}
                        onMouseLeave={e => { const b = e.currentTarget as HTMLButtonElement; b.style.color = "#555"; b.style.borderColor = "#222"; }}
                    >LOGOUT</button>
                </div>
            </header>

            {/* ── Banners ──────────────────────────────────────────────────── */}
            {actionError && (
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "1rem", background: "var(--red-bg)", borderBottom: "2px solid var(--red)", padding: "8px 16px", fontSize: "12px", color: "var(--red)" }}>
                    <span>// {actionError}</span>
                    <button onClick={() => setActionError(null)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--red)", fontSize: "14px", lineHeight: 1, padding: "0 4px" }}>✕</button>
                </div>
            )}
            {actionSuccess && (
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "1rem", background: "var(--green-bg)", borderBottom: "2px solid var(--green)", padding: "8px 16px", fontSize: "12px", color: "var(--green)" }}>
                    <span>// {actionSuccess}</span>
                    <button onClick={() => setActionSuccess(null)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--green)", fontSize: "14px", lineHeight: 1, padding: "0 4px" }}>✕</button>
                </div>
            )}

            {/* ── Stats row (5.2 skeleton, 5.5 responsive) ─────────────────── */}
            <div className="stat-grid">
                {[
                    { label: "ENDPOINTS",     value: endpointCount || "—", accent: "lime",   valueColor: "var(--t1)" },
                    { label: "ZOMBIES",       value: activeZombies  || "—", accent: "red",    valueColor: activeZombies > 0 ? "var(--red)" : "var(--t1)" },
                    { label: "QUARANTINED",   value: quarantined    || "—", accent: "lime",   valueColor: quarantined > 0 ? "var(--green)" : "var(--t1)" },
                    { label: "AWAITING",      value: awaitingCount  || "—", accent: "orange", valueColor: awaitingCount > 0 ? "var(--orange)" : "var(--t1)" },
                    { label: "HONEYPOT HITS", value: honeypotTotal  || "—", accent: "purple", valueColor: honeypotTotal > 0 ? "var(--purple)" : "var(--t1)" },
                ].map((card, i) => (
                    <div key={card.label} className={`stat-card-v2 accent-${card.accent}`} style={{
                        borderLeft:   i === 0 ? "1px solid var(--b1)" : "none",
                        borderRight:  "1px solid var(--b1)",
                        borderTop:    "none",
                        borderBottom: "none",
                    }}>
                        <div className="stat-label" style={{ color: "var(--t3)" }}>{card.label}</div>
                        <div className="stat-value" style={{ color: card.valueColor, fontSize: "30px" }}>
                            {/* 5.2 — skeleton during initial load */}
                            {initialLoad ? <span className="skeleton-bar" /> : card.value}
                        </div>
                    </div>
                ))}
            </div>

            {/* ── Quarantine strip ─────────────────────────────────────────── */}
            {gatewayConfig && gatewayConfig.quarantined_count > 0 && (
                <div style={{ padding: "7px 16px", background: "rgba(212,32,32,0.06)", borderBottom: "1px solid rgba(212,32,32,0.2)", borderLeft: "3px solid var(--red)", display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: "10px", fontWeight: 700, color: "var(--red)", letterSpacing: "0.08em", border: "1px solid var(--red)", padding: "2px 8px", background: "rgba(212,32,32,0.08)", flexShrink: 0, whiteSpace: "nowrap" }}>
                        ⊘ {gatewayConfig.quarantined_count} QUARANTINED
                    </span>
                    {gatewayConfig.quarantined.map((path: string) => (
                        <span key={path} style={{ fontSize: "11px", color: "var(--red)", fontFamily: "var(--mono)", background: "var(--s1)", border: "1px solid var(--b2)", padding: "2px 7px", whiteSpace: "nowrap" }}>
                            {path}
                        </span>
                    ))}
                    <span style={{ fontSize: "10px", color: "var(--t3)", fontFamily: "var(--mono)", marginLeft: "auto", whiteSpace: "nowrap" }}>
                        // 410 Gone · KrakenD enforced
                    </span>
                </div>
            )}

            {/* ── Main grid: Graph 60% + Incidents 40% (5.5 responsive) ───── */}
            <div className="main-grid">

                {/* Graph panel */}
                <div style={{ background: "#0a0a0a", borderRight: "1px solid var(--b1)", borderBottom: "1px solid var(--b1)", display: "flex", flexDirection: "column", height: "500px" }}>
                    <div style={{ background: "#0c0c0c", borderBottom: "1px solid #1e1e1e", padding: "10px 16px", display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                            <span style={{ fontFamily: "var(--sans)", fontSize: "10px", fontWeight: 700, color: "#b8ff00", letterSpacing: "0.14em", textTransform: "uppercase" }}>API Dependency Graph</span>
                            <span style={{ fontSize: "10px", color: "#333", border: "1px solid #1e1e1e", padding: "1px 7px", letterSpacing: "0.06em" }}>
                                {graphNodes.filter(n => n.type === "endpoint").length} endpoints
                            </span>
                            {/* 5.1 — panel-level reconnecting badge */}
                            {fetchError && <span className="reconnect-badge">⚠ Reconnecting…</span>}
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                            {selectedEndpoint && (
                                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                    <span style={{ fontSize: "11px", color: "#b8ff00", fontFamily: "var(--mono)", fontWeight: 700, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={selectedEndpoint}>
                                        {selectedEndpoint}
                                    </span>
                                    <button onClick={() => setSelectedEndpoint(null)} style={{ background: "none", border: "none", cursor: "pointer", color: "#333", fontSize: "12px", padding: "1px 4px" }}>✕</button>
                                </div>
                            )}
                            <span style={{ fontSize: "10px", color: "#333" }}>drag · scroll to zoom</span>
                        </div>
                    </div>
                    <div style={{ flex: 1, position: "relative", background: "#080808" }}>
                        <NetworkGraph
                            nodes={graphNodes}
                            edges={graphEdges}
                            onNodeClick={handleNodeClick}
                            selectedNodeId={selectedEndpoint}
                        />
                    </div>
                    {/* Legend + 5.1 last updated footer */}
                    <div style={{ padding: "6px 16px", borderTop: "1px solid #1e1e1e", display: "flex", gap: "12px", flexWrap: "wrap", background: "#0c0c0c", flexShrink: 0, alignItems: "center" }}>
                        {[
                            { color: "#7c3aed",       label: "gateway",     dashed: false },
                            { color: "var(--red)",    label: "zombie/crit", dashed: false },
                            { color: "var(--orange)", label: "zombie/high", dashed: false },
                            { color: "#f59e0b",       label: "drifting",    dashed: false },
                            { color: "var(--blue)",   label: "shadow",      dashed: true  },
                            { color: "#c026d3",       label: "orphaned",    dashed: true  },
                            { color: "var(--t3)",     label: "dormant",     dashed: false },
                            { color: "var(--green)",  label: "healthy",     dashed: false },
                        ].map(item => (
                            <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: "10px", color: "#444" }}>
                                <div style={{ width: 7, height: 7, border: `1px ${item.dashed ? "dashed" : "solid"} ${item.color}`, flexShrink: 0 }} />
                                {item.label}
                            </div>
                        ))}
                        {/* 5.1 — "Last updated Xs ago" in panel footer */}
                        {secsAgo !== null && (
                            <span style={{ marginLeft: "auto", fontSize: "10px", color: fetchError ? "var(--orange)" : "#333", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>
                                {fetchError ? `⚠ stale · ${formatSecsAgo(secsAgo)}` : `updated ${formatSecsAgo(secsAgo)}`}
                            </span>
                        )}
                    </div>
                </div>

                {/* Incidents panel */}
                <div style={{ height: "500px", borderBottom: "1px solid var(--b1)", borderRight: "1px solid var(--b1)" }}>
                    <IncidentPanel
                        incidents={incidents}
                        onApprove={handleApprove}
                        onReject={handleReject}
                        loadingId={loadingId}
                        selectedEndpoint={selectedEndpoint}
                        onViewDetail={handleViewDetail}
                        fetchError={fetchError}
                        secsAgo={secsAgo}
                    />
                </div>
            </div>

            {/* ── Bottom grid: Drift 65% + Honeypot 35% (5.5 responsive) ─── */}
            <div className="bottom-grid">
                <div style={{ borderRight: "1px solid var(--b1)", borderBottom: "1px solid var(--b1)", overflow: "hidden" }}>
                    <DriftTable
                        stats={driftStats}
                        onSelectEndpoint={handleSelectEndpoint}
                        selectedEndpoint={selectedEndpoint}
                    />
                </div>
                <div style={{ borderBottom: "1px solid var(--b1)", borderRight: "1px solid var(--b1)", overflow: "hidden" }}>
                    <HoneypotFeed events={honeypotEvents} />
                </div>
            </div>

            {/* ── Incident detail drawer ────────────────────────────────────── */}
            <IncidentDetailPanel
                threadId={detailThreadId}
                onClose={handleCloseDetail}
                onApprove={handleApprove}
                onReject={handleReject}
                loadingId={loadingId}
            />

        </div>
    );
}

// ── Export (AuthGuard is now in dashboard/layout.tsx) ─────────────────────────
function DashboardPageInner() {
    const searchParams = useSearchParams();
    const initialIncidentId = searchParams.get("incident");
    return <DashboardInner initialIncidentId={initialIncidentId} />;
}

export default function DashboardPage() {
    return (
        <Suspense>
            <DashboardPageInner />
        </Suspense>
    );
}
