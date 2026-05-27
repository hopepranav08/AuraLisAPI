"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
// AuthGuard is applied by dashboard/layout.tsx — no per-page import needed.

// ── Types ─────────────────────────────────────────────────────────────────────

interface AttackRequest { method: string; path: string; body?: string; delay: number; }
interface Scenario {
    id: string; name: string; subtitle: string; icon: string;
    color: string; severity: "CRITICAL" | "HIGH" | "MEDIUM";
    description: string; targetPath: string; requests: AttackRequest[];
}
interface TermLine { id: number; ts: string; text: string; kind: "info" | "req" | "ok" | "err" | "warn" | "sys"; }
interface DefLine  { id: number; ts: string; text: string; kind: "scan" | "drift" | "alarm" | "incident" | "action" | "done" | "sys"; }
type Phase = "idle" | "running" | "complete";

// ── Scenarios ─────────────────────────────────────────────────────────────────

const SCENARIOS: Scenario[] = [
    {
        id: "zombie_resurrection", name: "Zombie Resurrection", subtitle: "Burst on dormant endpoint",
        icon: "Z", color: "var(--red)", severity: "CRITICAL",
        description: "An attacker hammers a dormant endpoint that has had zero traffic for weeks. Triggers the Page-Hinkley drift alarm — the textbook zombie API signature.",
        targetPath: "/api/v1/legacy-payments",
        requests: Array.from({ length: 20 }, () => ({ method: "GET", path: "/api/v1/legacy-payments", delay: 140 })),
    },
    {
        id: "data_exfil", name: "Data Exfiltration", subtitle: "PII scrape on deprecated endpoints",
        icon: "X", color: "var(--orange)", severity: "HIGH",
        description: "High-frequency probing of deprecated payment and user APIs to harvest PII records. Triggers active_zombie classification with is_pii_exposed=true.",
        targetPath: "/api/v1/payments",
        requests: [
            ...Array.from({ length: 8 }, () => ({ method: "GET", path: "/api/v1/payments", delay: 180 })),
            ...Array.from({ length: 7 }, () => ({ method: "GET", path: "/api/v1/users", delay: 180 })),
        ],
    },
    {
        id: "shadow_probe", name: "Shadow API Discovery", subtitle: "Probe undocumented internal paths",
        icon: "S", color: "var(--purple)", severity: "MEDIUM",
        description: "Scans paths absent from the OpenAPI spec — internal configs, v2 endpoints, debug routes. Triggers shadow API classification.",
        targetPath: "/api/v1/internal/config",
        requests: [
            { method: "GET", path: "/api/v1/internal/config", delay: 250 },
            { method: "GET", path: "/api/v2/users", delay: 220 },
            { method: "GET", path: "/api/v1/internal/admin", delay: 220 },
            { method: "GET", path: "/api/v2/payments", delay: 220 },
            { method: "GET", path: "/api/v1/debug/env", delay: 250 },
            { method: "GET", path: "/api/v1/internal/config", delay: 220 },
        ],
    },
    {
        id: "cred_harvest", name: "Credential Harvest", subtitle: "Brute-force deprecated auth",
        icon: "C", color: "var(--blue)", severity: "HIGH",
        description: "Credential stuffing against a deprecated authentication endpoint. Exposes PII and password data through a forgotten login surface.",
        targetPath: "/api/v1/auth/login",
        requests: Array.from({ length: 12 }, (_, i) => ({
            method: "POST", path: "/api/v1/auth/login",
            body: JSON.stringify({ username: `user${i}@example.com`, password: "hunter2" }),
            delay: 230,
        })),
    },
    {
        id: "full_spectrum", name: "Full Spectrum", subtitle: "All vectors simultaneously",
        icon: "F", color: "#4afa7a", severity: "CRITICAL",
        description: "Combines all attack vectors: zombie burst, data exfil, shadow probe, and credential harvest. Tests complete AuralisAPI detection coverage.",
        targetPath: "/api/v1/legacy-payments",
        requests: [
            { method: "GET",  path: "/api/v1/legacy-payments", delay: 100 },
            { method: "GET",  path: "/api/v1/payments",        delay: 100 },
            { method: "GET",  path: "/api/v1/users",           delay: 100 },
            { method: "GET",  path: "/api/v1/internal/config", delay: 100 },
            { method: "POST", path: "/api/v1/auth/login",      delay: 100 },
            ...Array.from({ length: 15 }, () => ({ method: "GET", path: "/api/v1/legacy-payments", delay: 100 })),
            { method: "GET",  path: "/api/v2/users",    delay: 100 },
            { method: "GET",  path: "/api/v1/payments", delay: 100 },
        ],
    },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

let _lid = 0;
function nowTs() { return new Date().toISOString().split("T")[1].slice(0, 12); }
function mkT(text: string, kind: TermLine["kind"]): TermLine { return { id: ++_lid, ts: nowTs(), text, kind }; }
function mkD(text: string, kind: DefLine["kind"]): DefLine  { return { id: ++_lid, ts: nowTs(), text, kind }; }

async function safeFetch<T>(url: string, opts?: RequestInit): Promise<T | null> {
    try {
        const extraHeaders: Record<string, string> = {};
        if (url.startsWith("/brain")) {
            const token = typeof window !== "undefined" ? localStorage.getItem("auralis_brain_token") : null;
            if (token) extraHeaders["Authorization"] = `Bearer ${token}`;
        }
        const r = await fetch(url, {
            signal: AbortSignal.timeout(5000),
            ...opts,
            headers: { ...extraHeaders, ...(opts?.headers as Record<string, string> ?? {}) },
        });
        if (!r.ok) return null;
        return await r.json() as T;
    } catch { return null; }
}

// ── Terminal Components ───────────────────────────────────────────────────────

// Attacker — intentionally dark (full black) terminal for dramatic contrast
const TERM_COLORS: Record<TermLine["kind"], string> = {
    info: "#9ca3af", req: "#60a5fa", ok: "#4ade80",
    err: "#f87171", warn: "#fb923c", sys: "#c084fc",
};

function AttackerTerminal({ lines, title }: { lines: TermLine[]; title: string }) {
    const ref = useRef<HTMLDivElement>(null);
    useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [lines.length]);
    return (
        <div style={{ height: "100%", display: "flex", flexDirection: "column", background: "#0a0a0a", overflow: "hidden" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 12px", background: "#111", borderBottom: "1px solid #222", flexShrink: 0 }}>
                <span style={{ fontSize: "10px", color: "#555", fontFamily: "var(--mono)" }}>// {title}</span>
            </div>
            <div ref={ref} style={{ flex: 1, overflowY: "auto", padding: "10px 14px", fontFamily: "var(--mono)", fontSize: "11px", lineHeight: 1.8 }}>
                {lines.length === 0
                    ? <span style={{ color: "#333" }}>$ select scenario and launch_</span>
                    : lines.map(l => (
                        <div key={l.id} style={{ display: "flex", gap: "10px" }}>
                            <span style={{ color: "#333", flexShrink: 0 }}>{l.ts}</span>
                            <span style={{ color: TERM_COLORS[l.kind], wordBreak: "break-all" }}>{l.text}</span>
                        </div>
                    ))
                }
                <span style={{ display: "inline-block", width: 6, height: "1em", background: "var(--red)", verticalAlign: "text-bottom", animation: "blink 1s step-end infinite" }} />
            </div>
        </div>
    );
}

// Defender — light bg with ink text and colored event highlights
const DEF_COLORS: Record<DefLine["kind"], string> = {
    scan: "var(--blue)", drift: "var(--orange)", alarm: "var(--red)",
    incident: "var(--red)", action: "var(--green)", done: "#4afa7a", sys: "var(--t3)",
};
const DEF_ICONS: Record<DefLine["kind"], string> = {
    scan: "◉", drift: "↑", alarm: "⚠", incident: "⚡", action: "→", done: "✓", sys: "·",
};

function DefenderConsole({ lines, phScore, incidents, detectionMs }: {
    lines: DefLine[]; phScore: number; incidents: number; detectionMs: number | null;
}) {
    const ref = useRef<HTMLDivElement>(null);
    useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [lines.length]);

    const phPct   = Math.min(100, (phScore / 30) * 100);
    const phColor = phScore > 25 ? "var(--red)" : phScore > 10 ? "var(--orange)" : "var(--green)";
    const phFill  = phScore > 25 ? "score-bar__fill--red" : phScore > 10 ? "score-bar__fill--orange" : "score-bar__fill--green";

    return (
        <div style={{ height: "100%", display: "flex", flexDirection: "column", background: "var(--s1)", overflow: "hidden" }}>
            <div style={{ padding: "8px 14px", background: "var(--s2)", borderBottom: "1px solid var(--b1)", flexShrink: 0 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                    <span style={{ fontSize: "10px", fontWeight: 700, color: "var(--t2)", textTransform: "uppercase", letterSpacing: "0.1em", fontFamily: "var(--sans)" }}>
                        AURALIS · KERNEL DEFENDER
                    </span>
                    <div style={{ display: "flex", gap: "4px" }}>
                        {incidents > 0 && <span className="badge badge--critical">{incidents} INCIDENT{incidents !== 1 ? "S" : ""}</span>}
                        {detectionMs !== null && <span className="badge badge--ok">⚡ {(detectionMs / 1000).toFixed(1)}s</span>}
                    </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontSize: "10px", color: "var(--t3)", fontFamily: "var(--mono)", flexShrink: 0 }}>PH</span>
                    <div className="score-bar" style={{ flex: 1 }}>
                        <div className={`score-bar__fill ${phFill}`} style={{ width: `${phPct}%` }} />
                    </div>
                    <span style={{ fontSize: "11px", color: phColor, fontWeight: 700, fontFamily: "var(--mono)", minWidth: 32, textAlign: "right" }}>
                        {phScore.toFixed(1)}
                    </span>
                </div>
            </div>
            <div ref={ref} style={{ flex: 1, overflowY: "auto", padding: "8px 14px", fontFamily: "var(--mono)", fontSize: "11px", lineHeight: 1.8 }}>
                {lines.length === 0 ? (
                    <div style={{ height: "100%", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: "8px", textAlign: "center" }}>
                        <span style={{ color: "var(--green)", fontSize: "24px" }}>◎</span>
                        <span style={{ color: "var(--t3)", fontSize: "11px" }}>// kernel sensor active — awaiting attack</span>
                    </div>
                ) : lines.map(l => (
                    <div key={l.id} style={{ display: "flex", gap: "8px", alignItems: "flex-start", marginBottom: "1px" }}>
                        <span style={{ color: "var(--t3)", flexShrink: 0, minWidth: "5.5rem" }}>{l.ts}</span>
                        <span style={{ color: DEF_COLORS[l.kind], flexShrink: 0, fontWeight: 700 }}>{DEF_ICONS[l.kind]}</span>
                        <span style={{ color: l.kind === "alarm" || l.kind === "incident" || l.kind === "done" ? DEF_COLORS[l.kind] : "var(--t2)", wordBreak: "break-all" }}>{l.text}</span>
                    </div>
                ))}
            </div>
        </div>
    );
}

// ── Scenario Card ─────────────────────────────────────────────────────────────

function ScenarioCard({ s, selected, disabled, onClick }: {
    s: Scenario; selected: boolean; disabled: boolean; onClick: () => void;
}) {
    const sevClass = s.severity === "CRITICAL" ? "badge--critical" : s.severity === "HIGH" ? "badge--high" : "badge--medium";
    return (
        <button
            onClick={onClick}
            disabled={disabled}
            style={{
                width: "100%", textAlign: "left", padding: "12px",
                background: selected ? "rgba(74,250,122,0.06)" : "var(--s1)",
                border: "none",
                borderLeft: selected ? `3px solid ${s.color}` : "3px solid transparent",
                borderRadius: 0,
                cursor: disabled ? "not-allowed" : "pointer",
                transition: "background 0.1s, border-left-color 0.1s",
                outline: "none",
            }}
            onMouseEnter={e => { if (!selected && !disabled) (e.currentTarget as HTMLButtonElement).style.background = "var(--s2)"; }}
            onMouseLeave={e => { if (!selected && !disabled) (e.currentTarget as HTMLButtonElement).style.background = selected ? "rgba(74,250,122,0.06)" : "var(--s1)"; }}
        >
            <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "4px" }}>
                <span style={{
                    display: "inline-flex", alignItems: "center", justifyContent: "center",
                    width: 22, height: 22,
                    background: selected ? s.color : "var(--s3)",
                    color: selected ? "#fff" : s.color,
                    fontSize: "10px", fontWeight: 800, fontFamily: "var(--sans)", flexShrink: 0,
                    border: `1px solid ${s.color}`,
                }}>
                    {s.icon}
                </span>
                <span style={{ fontFamily: "var(--sans)", fontWeight: 700, fontSize: "12px", color: "var(--t1)" }}>{s.name}</span>
                <span className={`badge ${sevClass}`} style={{ marginLeft: "auto" }}>{s.severity}</span>
            </div>
            <div style={{ fontSize: "10px", color: "var(--t3)", marginBottom: "3px", fontFamily: "var(--mono)" }}>{s.subtitle}</div>
            <div style={{ fontFamily: "var(--mono)", fontSize: "10px", color: s.color, fontWeight: 600 }}>{s.targetPath}</div>
        </button>
    );
}

// ── Main Component ────────────────────────────────────────────────────────────

function AttackArenaInner() {
    const router = useRouter();
    const [scenarioId,   setScenarioId]   = useState("zombie_resurrection");
    const [phase,        setPhase]        = useState<Phase>("idle");
    const [termLines,    setTermLines]    = useState<TermLine[]>([]);
    const [defLines,     setDefLines]     = useState<DefLine[]>([]);
    const [phScore,      setPhScore]      = useState(0);
    const [incidents,    setIncidents]    = useState(0);
    const [detectionMs,  setDetectionMs]  = useState<number | null>(null);
    const [elapsed,      setElapsed]      = useState(0);
    const [sentCount,    setSentCount]    = useState(0);
    const [triggeredIds, setTriggeredIds] = useState<string[]>([]);

    const startRef       = useRef(0);
    const prevIncRef     = useRef(0);
    const detectedRef    = useRef(false);
    const phBandRef      = useRef<"normal" | "warn" | "alarm">("normal");
    const existingIdsRef = useRef<Set<string>>(new Set());
    const pollRef        = useRef<ReturnType<typeof setInterval> | null>(null);
    const timerRef       = useRef<ReturnType<typeof setInterval> | null>(null);
    const mountRef       = useRef(true);

    useEffect(() => {
        mountRef.current = true;
        return () => {
            mountRef.current = false;
            if (pollRef.current)  clearInterval(pollRef.current);
            if (timerRef.current) clearInterval(timerRef.current);
        };
    }, []);

    const addT = useCallback((text: string, kind: TermLine["kind"]) => {
        if (mountRef.current) setTermLines(p => [...p, mkT(text, kind)]);
    }, []);
    const addD = useCallback((text: string, kind: DefLine["kind"]) => {
        if (mountRef.current) setDefLines(p => [...p, mkD(text, kind)]);
    }, []);

    const scenario = SCENARIOS.find(s => s.id === scenarioId) ?? SCENARIOS[0];

    function startDefensePoll(initCount: number) {
        prevIncRef.current  = initCount;
        detectedRef.current = false;
        phBandRef.current   = "normal";
        const seenIds = new Set(existingIdsRef.current);
        if (pollRef.current) clearInterval(pollRef.current);
        pollRef.current = setInterval(async () => {
            if (!mountRef.current) return;
            const [drift, inc] = await Promise.all([
                safeFetch<Array<{ endpoint: string; ph_score: number }>>("/drift/stats"),
                safeFetch<{ incidents: Array<{ thread_id: string; endpoint: string; classification: string; severity: string }> }>("/brain/incidents"),
            ]);
            if (!mountRef.current) return;

            if (drift?.length) {
                const max = Math.max(...drift.map(d => d.ph_score ?? 0));
                setPhScore(max);
                const band: "normal" | "warn" | "alarm" = max > 25 ? "alarm" : max > 10 ? "warn" : "normal";
                if (band !== phBandRef.current) {
                    phBandRef.current = band;
                    if (band === "alarm") addD(`Page-Hinkley ALARM — PH=${max.toFixed(1)} > λ=25`, "alarm");
                    else if (band === "warn") addD(`Drift detected — PH=${max.toFixed(1)}/25`, "drift");
                }
            }

            if (inc?.incidents) {
                const newOnes = inc.incidents.filter(it => !seenIds.has(it.thread_id));
                if (newOnes.length > 0) {
                    if (!detectedRef.current) {
                        detectedRef.current = true;
                        const ms = Date.now() - startRef.current;
                        setDetectionMs(ms);
                        addD(`Detection at ${(ms / 1000).toFixed(2)}s after attack start`, "done");
                    }
                    newOnes.forEach(it => {
                        seenIds.add(it.thread_id);
                        addD(`Incident: ${it.endpoint} → [${(it.classification ?? "UNKNOWN").toUpperCase()}]  sev=${it.severity ?? "?"}`, "incident");
                        addD(`AI plan: quarantine_gateway + spin_up_honeypot`, "action");
                    });
                    prevIncRef.current = inc.incidents.length;
                    // Track only new incidents from this run (seenIds started from pre-existing set)
                    setIncidents(seenIds.size - existingIdsRef.current.size);
                }
            }
        }, 900);
    }

    function stopDefensePoll() {
        if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    }

    async function handleLaunch() {
        if (phase === "running") return;

        _lid = 0;
        setTermLines([]); setDefLines([]);
        setPhScore(0); setIncidents(0); setDetectionMs(null);
        setElapsed(0); setSentCount(0); setTriggeredIds([]);
        setPhase("running");
        startRef.current = Date.now();

        if (timerRef.current) clearInterval(timerRef.current);
        timerRef.current = setInterval(() => {
            if (mountRef.current) setElapsed(Date.now() - startRef.current);
        }, 100);

        const existingIncData = await safeFetch<{ incidents: Array<{ thread_id: string }>; total: number }>("/brain/incidents");
        const existingIds = new Set((existingIncData?.incidents ?? []).map(i => i.thread_id));
        existingIdsRef.current = existingIds;
        const initCount = existingIds.size;

        addT(`=== ${scenario.name.toUpperCase()} ===`, "sys");
        addT(`target: ${scenario.targetPath}`, "info");
        addT(`payload: ${scenario.requests.length} requests  severity: ${scenario.severity}`, "info");
        addT(`launching attack sequence...`, "warn");

        addD(`Attack Arena — scenario: ${scenario.name}`, "sys");
        addD(`eBPF kernel hook: active`, "scan");
        addD(`monitoring target: ${scenario.targetPath}`, "scan");
        addD(`Page-Hinkley λ=25.0 watchdog armed`, "scan");

        startDefensePoll(initCount);

        for (let i = 0; i < scenario.requests.length; i++) {
            if (!mountRef.current) break;
            const req = scenario.requests[i];
            await new Promise<void>(res => setTimeout(res, req.delay));

            const t0 = Date.now();
            let status = "—";
            try {
                const opts: RequestInit = { method: req.method, signal: AbortSignal.timeout(3000) };
                if (req.body) { opts.body = req.body; opts.headers = { "Content-Type": "application/json" }; }
                const r = await fetch(req.path, opts);
                status = String(r.status);
                // KrakenD CE proxy/static returns HTTP 200 with body {error:"Gone",code:410}
                // even when status_code:410 is configured — check body to detect blocked paths.
                if (status === "200") {
                    try {
                        const bd = await r.clone().json();
                        if (bd?.code === 410 || bd?.error === "Gone") status = "410";
                    } catch { /* body not JSON — leave status as-is */ }
                }
            } catch { status = "TMO"; }

            const lat  = Date.now() - t0;
            // 410 / Gone = blocked by gateway (green — attacker is stopped)
            // 200 = request got through (orange warn — not yet quarantined)
            // 4xx/5xx = other error
            const httpKind: TermLine["kind"] =
                status === "410" ? "ok" :
                status.startsWith("2") ? "warn" :
                status.startsWith("4") || status.startsWith("5") ? "err" : "info";
            addT(`${req.method.padEnd(6)} ${req.path.padEnd(38)} ${status}  ${lat}ms`, httpKind);
            void fetch("/brain/sensor/ingest", {
                method: "POST",
                headers: { "Content-Type": "application/json", "X-Sensor-ID": "attack-arena" },
                body: JSON.stringify({
                    event_type:  "http_event",
                    method:      req.method,
                    path:        req.path,
                    status_code: parseInt(status) || 0,
                    source:      "plain",
                    direction:   "ingress",
                    pid: 9999, tid: 9999,
                    timestamp_ns: Date.now() * 1000000,
                }),
            }).catch(() => {});
            setSentCount(i + 1);
        }

        addT(`attack complete — ${scenario.requests.length} requests sent`, "sys");
        addD(`attack sequence ended. invoking remediation AI...`, "sys");

        const remResult = await safeFetch<{ thread_id: string; status: string }>(
            "/brain/remediate",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ path: scenario.targetPath, method: "GET", reason: scenario.id }),
            }
        );

        if (remResult?.thread_id) {
            addT(`brain trigger fired — thread=${remResult.thread_id.slice(0, 8)}…`, "sys");
            addD(`remediation thread: ${remResult.thread_id.slice(0, 8)}…`, "action");
            addD(`AI pipeline: ingest → analyze → classify → plan → interrupt`, "action");
            setTriggeredIds((prev: string[]) => [...prev, remResult.thread_id]);
        } else {
            addD(`brain triggered — polling for response…`, "action");
        }

        await new Promise<void>(res => setTimeout(res, 8000));
        stopDefensePoll();

        const [finalDrift, finalInc] = await Promise.all([
            safeFetch<Array<{ endpoint: string; ph_score: number }>>("/drift/stats"),
            safeFetch<{ incidents: Array<{ thread_id: string; endpoint: string; classification: string; severity: string; status: string }> }>("/brain/incidents"),
        ]);

        if (finalDrift?.length) setPhScore(Math.max(...finalDrift.map(d => d.ph_score ?? 0)));

        addD(`=== ATTACK SUMMARY ===`, "sys");
        if (finalInc?.incidents?.length) {
            const newIncs = (finalInc?.incidents ?? []).filter(it => !existingIds.has(it.thread_id));
            setIncidents(newIncs.length); // show only new incidents from this run
            if (newIncs.length > 0) {
                newIncs.forEach(it => addD(`  ${it.endpoint}  [${(it.classification ?? "?").toUpperCase()}]  ${it.status}`, "done"));
                addD(`quarantine plan ready — awaiting human approval in Dashboard`, "done");
            } else {
                addD(`no new incidents — brain may still be processing`, "sys");
                addD(`check the Dashboard to see pending incidents`, "sys");
            }
        } else {
            addD(`no incidents retrieved — check Dashboard`, "sys");
        }
        addT(`ghost mode complete. go to Dashboard to approve enforcement.`, "sys");

        if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
        if (mountRef.current) setPhase("complete");
    }

    function handleLogout() {
        localStorage.removeItem("auralis_auth");
        router.replace("/login");
    }

    const total  = scenario.requests.length;
    const pct    = total > 0 ? Math.round((sentCount / total) * 100) : 0;
    const phFill = phScore > 25 ? "score-bar__fill--red" : phScore > 10 ? "score-bar__fill--orange" : "score-bar__fill--green";

    return (
        <div style={{ height: "100vh", background: "var(--bg)", fontFamily: "var(--mono)", display: "flex", flexDirection: "column", overflow: "hidden" }}>

            {/* ── Header ── */}
            <header style={{
                position: "sticky", top: 0, zIndex: 50, height: 48, padding: "0 16px",
                display: "flex", alignItems: "center", gap: "10px",
                background: "var(--s1)", borderBottom: "2px solid var(--t1)",
            }}>
                <Link href="/" style={{ textDecoration: "none", flexShrink: 0 }}>
                    <span style={{ fontFamily: "var(--sans)", fontSize: "14px", fontWeight: 800, color: "var(--t1)" }}>[AURALIS]</span>
                </Link>
                <span style={{ color: "var(--b3)" }}>/</span>
                <Link href="/dashboard" style={{ fontSize: "12px", color: "var(--t2)", textDecoration: "none" }}>dashboard</Link>
                <span style={{ color: "var(--b3)" }}>/</span>
                <span style={{ fontSize: "12px", color: "var(--t1)", fontWeight: 600 }}>attack-arena</span>

                <div style={{ width: "1px", height: "20px", background: "var(--b2)", margin: "0 4px" }} />
                <span style={{ fontSize: "11px", color: "var(--red)", fontFamily: "var(--sans)", fontWeight: 700, letterSpacing: "0.06em" }}>◈ GHOST MODE</span>

                <div style={{ flex: 1 }} />

                {phase === "running" && (
                    <span className="badge badge--critical" style={{ animation: "pulse-ok 1s infinite" }}>
                        ⬤ LIVE · {(elapsed / 1000).toFixed(1)}s
                    </span>
                )}
                {phase === "complete" && (
                    <span className="badge badge--ok">✓ COMPLETE · {(elapsed / 1000).toFixed(1)}s</span>
                )}

                <Link href="/dashboard" style={{ textDecoration: "none" }}>
                    <button className="btn btn--sm">← DASHBOARD</button>
                </Link>
                <button onClick={handleLogout} className="btn btn--sm">LOGOUT</button>
            </header>

            {/* ── Scenario Selector ── */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", borderBottom: "1px solid var(--b1)", background: "var(--s1)" }}>
                {SCENARIOS.map((s, i) => (
                    <div key={s.id} style={{ borderRight: i < 4 ? "1px solid var(--b1)" : "none" }}>
                        <ScenarioCard
                            s={s} selected={scenarioId === s.id}
                            disabled={phase === "running"}
                            onClick={() => { if (phase !== "running") setScenarioId(s.id); }}
                        />
                    </div>
                ))}
            </div>

            {/* ── Launch Bar ── */}
            <div style={{
                display: "flex", alignItems: "center", gap: "12px",
                padding: "10px 16px", background: "var(--s2)",
                borderBottom: "2px solid var(--t1)",
            }}>
                <button
                    onClick={handleLaunch}
                    disabled={phase === "running"}
                    className={`btn btn--lg ${phase !== "running" ? "btn--solid" : ""}`}
                    style={{ flexShrink: 0 }}
                >
                    {phase === "running" ? (
                        <><span className="spinner" />RUNNING…</>
                    ) : "▸ LAUNCH ATTACK"}
                </button>

                {phase === "running" && (
                    <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 4 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px" }}>
                            <span style={{ color: "var(--t2)" }}>{scenario.name} · {sentCount}/{total} requests</span>
                            <span style={{ color: "var(--t3)" }}>{pct}%</span>
                        </div>
                        <div className="score-bar" style={{ height: 6 }}>
                            <div className={`score-bar__fill ${phFill}`} style={{ width: `${pct}%` }} />
                        </div>
                    </div>
                )}

                {phase === "complete" && (
                    <div style={{ display: "flex", gap: "8px" }}>
                        {detectionMs !== null && (
                            <div style={{ padding: "6px 14px", background: "var(--green-bg)", border: "1px solid var(--green)" }}>
                                <div style={{ fontSize: "10px", color: "var(--t3)", marginBottom: 2, fontFamily: "var(--sans)", fontWeight: 700, textTransform: "uppercase" }}>DETECT TIME</div>
                                <div style={{ fontSize: "20px", fontWeight: 800, color: "var(--green)", fontFamily: "var(--sans)" }}>{(detectionMs / 1000).toFixed(2)}s</div>
                            </div>
                        )}
                        <div style={{ padding: "6px 14px", background: "rgba(124,58,237,0.07)", border: "1px solid var(--purple)" }}>
                            <div style={{ fontSize: "10px", color: "var(--t3)", marginBottom: 2, fontFamily: "var(--sans)", fontWeight: 700, textTransform: "uppercase" }}>INCIDENTS</div>
                            <div style={{ fontSize: "20px", fontWeight: 800, color: "var(--purple)", fontFamily: "var(--sans)" }}>{incidents}</div>
                        </div>
                        <div style={{ padding: "6px 14px", background: "var(--red-bg)", border: "1px solid var(--red)" }}>
                            <div style={{ fontSize: "10px", color: "var(--t3)", marginBottom: 2, fontFamily: "var(--sans)", fontWeight: 700, textTransform: "uppercase" }}>PH PEAK</div>
                            <div style={{ fontSize: "20px", fontWeight: 800, color: "var(--red)", fontFamily: "var(--sans)" }}>{phScore.toFixed(1)}</div>
                        </div>
                    </div>
                )}

                {phase === "idle" && (
                    <span style={{ fontSize: "12px", color: "var(--t3)" }}>
                        {scenario.name} · {scenario.requests.length} req · <span style={{ color: scenario.color }}>{scenario.severity}</span>
                    </span>
                )}

                <div style={{ flex: 1 }} />

                <Link href="/dashboard" style={{ textDecoration: "none" }}>
                    <button className="btn btn--sm">↗ MANAGE INCIDENTS</button>
                </Link>
            </div>

            {/* ── Split Screen: Attacker | Defender ── */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", flex: 1, minHeight: 0, overflow: "hidden" }}>
                {/* Attacker side */}
                <div style={{ borderRight: "1px solid var(--b2)", display: "flex", flexDirection: "column" }}>
                    <div style={{ background: "#111", borderBottom: "1px solid #222", padding: "6px 14px", display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                        <span style={{
                            width: 7, height: 7, background: phase === "running" ? "var(--red)" : "#444",
                            display: "inline-block", animation: phase === "running" ? "pulse-ok 1s infinite" : "none",
                        }} />
                        <span style={{ fontFamily: "var(--sans)", fontWeight: 700, fontSize: "10px", color: "var(--red)", textTransform: "uppercase", letterSpacing: "0.1em" }}>ATTACKER</span>
                        {phase === "running" && <span style={{ fontSize: "10px", color: "#555" }}>live</span>}
                    </div>
                    <div style={{ flex: 1 }}>
                        <AttackerTerminal lines={termLines} title={`attacker@ghost  ${scenario.targetPath}`} />
                    </div>
                </div>
                {/* Defender side */}
                <div style={{ display: "flex", flexDirection: "column" }}>
                    <div style={{ background: "var(--s2)", borderBottom: "1px solid var(--b1)", padding: "6px 14px", display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                        <span style={{ width: 7, height: 7, background: "var(--green)", display: "inline-block", animation: "pulse-ok 2s infinite" }} />
                        <span style={{ fontFamily: "var(--sans)", fontWeight: 700, fontSize: "10px", color: "var(--green)", textTransform: "uppercase", letterSpacing: "0.1em" }}>AURALISAPI DEFENDER</span>
                        {phase === "running" && <span style={{ fontSize: "10px", color: "var(--t3)" }}>detecting</span>}
                    </div>
                    <div style={{ flex: 1 }}>
                        <DefenderConsole
                            lines={defLines} phScore={phScore}
                            incidents={incidents} detectionMs={detectionMs}
                        />
                    </div>
                </div>
            </div>

            {/* ── Results strip ── */}
            {phase === "complete" && (
                <div style={{ background: "var(--green-bg)", borderTop: "2px solid var(--t1)", padding: "10px 16px", display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
                    <span style={{ fontSize: "11px", color: "var(--t1)", fontFamily: "var(--sans)", fontWeight: 700 }}>// ATTACK COMPLETE</span>
                    <span style={{ color: "var(--b3)" }}>·</span>
                    {triggeredIds.length > 0 ? (
                        <>
                            <span style={{ fontSize: "11px", color: "var(--t2)" }}>open incident:</span>
                            {triggeredIds.map((id: string) => (
                                <Link key={id} href={`/dashboard?incident=${id}`} style={{ textDecoration: "none" }}>
                                    <button className="btn btn--solid btn--sm" style={{ fontFamily: "var(--mono)", fontSize: "10px" }}>
                                        {id.slice(0, 8)}… →
                                    </button>
                                </Link>
                            ))}
                            <span style={{ color: "var(--b3)" }}>·</span>
                        </>
                    ) : null}
                    <Link href="/dashboard" style={{ textDecoration: "none" }}>
                        <button className="btn btn--sm">DASHBOARD</button>
                    </Link>
                    <span style={{ fontSize: "11px", color: "var(--t2)" }}>to approve enforcement</span>
                </div>
            )}
        </div>
    );
}

export default function AttackArenaPage() {
    return <AttackArenaInner />;
}
