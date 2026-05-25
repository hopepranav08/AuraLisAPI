"use client";

import { useEffect, useRef, useCallback } from "react";
import * as d3 from "d3";

export interface GraphNode extends d3.SimulationNodeDatum {
    id: string;
    label: string;
    type: "gateway" | "endpoint";
    classification: string | null;
    severity: string | null;
    is_pii: boolean;
    ph_score: number;
    dormant: boolean;
    traffic: number;
}

export interface GraphEdge {
    source: string;
    target: string;
}

interface Props {
    nodes: GraphNode[];
    edges: GraphEdge[];
    onNodeClick: (node: GraphNode) => void;
    selectedNodeId: string | null;
}

function nodeRadius(d: GraphNode): number {
    if (d.type === "gateway") return 32;
    return Math.max(14, Math.min(22, 14 + (d.traffic / 8)));
}

function nodeFill(d: GraphNode): string {
    if (d.type === "gateway") return "#1a1a1a";
    switch (d.classification) {
        case "active_zombie":  return d.severity === "critical" ? "#1a0000" : "#1a0d00";
        case "dormant_zombie": return "#111111";
        case "shadow":         return "#0d0d1a";
        case "drifting":       return "#1a1500";
        case "orphaned":       return "#1a001a";
        default:               return "#0d1a0d";
    }
}

function nodeStroke(d: GraphNode): string {
    if (d.type === "gateway") return "#a855f7";
    switch (d.classification) {
        case "active_zombie":  return d.severity === "critical" ? "#ff2727" : "#ff8c00";
        case "dormant_zombie": return "#444444";
        case "shadow":         return "#4080ff";
        case "drifting":       return "#f59e0b";
        case "orphaned":       return "#c026d3";
        default:               return "#22c55e";
    }
}

function nodeStrokeWidth(d: GraphNode): number {
    if (d.type === "gateway") return 3;
    return 1.5;
}

function edgeStroke(target: GraphNode | null): string {
    if (!target) return "rgba(255,255,255,0.08)";
    if (target.type === "gateway") return "rgba(168,85,247,0.25)";
    switch (target.classification) {
        case "active_zombie":
            return target.severity === "critical" ? "rgba(255,39,39,0.4)" : "rgba(255,140,0,0.35)";
        case "dormant_zombie": return "rgba(68,68,68,0.35)";
        case "shadow":         return "rgba(64,128,255,0.3)";
        case "drifting":       return "rgba(245,158,11,0.3)";
        case "orphaned":       return "rgba(192,38,211,0.25)";
        default:               return "rgba(34,197,94,0.25)";
    }
}

function edgeMarker(target: GraphNode | null): string {
    if (!target) return "url(#arrow-default)";
    if (target.type === "gateway") return "url(#arrow-gateway)";
    switch (target.classification) {
        case "active_zombie":
            return target.severity === "critical" ? "url(#arrow-zombie-crit)" : "url(#arrow-zombie-high)";
        case "dormant_zombie": return "url(#arrow-dormant)";
        case "shadow":         return "url(#arrow-shadow)";
        case "drifting":       return "url(#arrow-drifting)";
        case "orphaned":       return "url(#arrow-orphaned)";
        default:               return "url(#arrow-healthy)";
    }
}

export default function NetworkGraph({ nodes, edges, onNodeClick, selectedNodeId }: Props) {
    const svgRef       = useRef<SVGSVGElement>(null);
    const containerRef = useRef<HTMLDivElement>(null);
    const simRef       = useRef<d3.Simulation<GraphNode, GraphEdge> | null>(null);
    const onClickRef   = useRef(onNodeClick);
    const selectedRef  = useRef(selectedNodeId);
    // Keep latest prop values in refs so buildGraph does not need them as
    // closure deps — prevents the simulation from being torn down and restarted
    // on every 5-second poll cycle when the data hasn't actually changed.
    const nodesRef     = useRef(nodes);
    const edgesRef     = useRef(edges);
    // Digest of the last rendered data; guards against spurious rebuilds.
    const digestRef    = useRef("");

    useEffect(() => { onClickRef.current  = onNodeClick; },    [onNodeClick]);
    useEffect(() => { selectedRef.current = selectedNodeId; }, [selectedNodeId]);

    // Sync refs during render — safe because refs are stable and this is
    // synchronous (not inside an effect), ensuring buildGraph always reads the
    // latest props no matter when it fires.
    nodesRef.current = nodes;
    edgesRef.current = edges;

    // buildGraph is a stable function (empty dep array) that reads from refs.
    // This prevents React from creating a new function reference on every render,
    // which would retrigger the main useEffect and restart the D3 simulation.
    const buildGraph = useCallback(() => {
        const nodes = nodesRef.current;
        const edges = edgesRef.current;
        const svgEl = svgRef.current;
        const el    = containerRef.current;
        if (!svgEl || !el) return;

        if (simRef.current) { simRef.current.stop(); simRef.current = null; }
        d3.select(svgEl).selectAll("*").remove();

        const W = el.clientWidth  || 700;
        const H = el.clientHeight || 460;
        if (nodes.length === 0) return;

        // Deep-clone so we don't mutate props
        const simNodes: GraphNode[] = nodes.map(n => ({ ...n }));
        const nodeMap = new Map<string, GraphNode>(simNodes.map(n => [n.id, n]));
        const simEdges = edges.map(e => ({ ...e }));

        // Pre-position nodes in a radial layout for a stable start
        const gateway = simNodes.find(n => n.type === "gateway");
        const endpts  = simNodes.filter(n => n.type === "endpoint");
        if (gateway) { gateway.fx = W / 2; gateway.fy = H / 2; }
        endpts.forEach((n, i) => {
            const angle = (i / endpts.length) * 2 * Math.PI - Math.PI / 2;
            const r = Math.min(W, H) * 0.32;
            n.x = W / 2 + r * Math.cos(angle);
            n.y = H / 2 + r * Math.sin(angle);
        });

        const svg = d3.select(svgEl)
            .attr("width", W)
            .attr("height", H)
            .style("background", "transparent");

        // Grid background + arrow marker defs
        const defs = svg.append("defs");
        const pattern = defs.append("pattern")
            .attr("id", "grid-bg")
            .attr("width", 40)
            .attr("height", 40)
            .attr("patternUnits", "userSpaceOnUse");
        pattern.append("path")
            .attr("d", "M 40 0 L 0 0 0 40")
            .attr("fill", "none")
            .attr("stroke", "#1a1a1a")
            .attr("stroke-width", "0.5");

        // Arrow markers for directed edges
        const markerColors: [string, string][] = [
            ["arrow-zombie-crit",  "#ff2727"],
            ["arrow-zombie-high",  "#ff8c00"],
            ["arrow-dormant",      "#444444"],
            ["arrow-shadow",       "#4080ff"],
            ["arrow-drifting",     "#f59e0b"],
            ["arrow-orphaned",     "#c026d3"],
            ["arrow-healthy",      "#22c55e"],
            ["arrow-gateway",      "#a855f7"],
            ["arrow-default",      "rgba(255,255,255,0.15)"],
        ];
        markerColors.forEach(([id, color]) => {
            defs.append("marker")
                .attr("id", id)
                .attr("markerWidth", 6)
                .attr("markerHeight", 6)
                .attr("refX", 6)
                .attr("refY", 3)
                .attr("orient", "auto")
                .append("path")
                .attr("d", "M0,0 L0,6 L6,3 z")
                .attr("fill", color)
                .attr("opacity", 0.8);
        });

        svg.append("rect").attr("width", "100%").attr("height", "100%").attr("fill", "url(#grid-bg)").attr("opacity", 0.8);

        // Zoom/pan layer
        const zoomG = svg.append("g").attr("class", "zoom-root");
        svg.call(
            d3.zoom<SVGSVGElement, unknown>()
                .scaleExtent([0.25, 5])
                .on("zoom", e => zoomG.attr("transform", e.transform))
        );

        // Edges
        const linkG = zoomG.append("g").attr("class", "links");
        const linkSel = linkG.selectAll<SVGLineElement, typeof simEdges[0]>("line")
            .data(simEdges)
            .join("line")
            .attr("stroke-width", 1.5)
            .attr("stroke-opacity", 0.9)
            .attr("stroke-linecap", "butt")
            .attr("stroke", d => {
                const tid = typeof d.target === "object" ? (d.target as GraphNode).id : d.target;
                return edgeStroke(nodeMap.get(tid) ?? null);
            })
            .attr("marker-end", d => {
                const tid = typeof d.target === "object" ? (d.target as GraphNode).id : d.target;
                return edgeMarker(nodeMap.get(tid) ?? null);
            });

        // Node groups
        const nodeG = zoomG.append("g").attr("class", "nodes");
        const nodeGroups = nodeG.selectAll<SVGGElement, GraphNode>("g")
            .data(simNodes, d => d.id)
            .join("g")
            .attr("class", "node")
            .style("cursor", d => d.type === "gateway" ? "default" : "pointer");

        // Pulse rings for active zombies — inner ring
        nodeGroups.filter(d => d.classification === "active_zombie")
            .append("circle")
            .attr("r", d => nodeRadius(d) + 8)
            .attr("fill", "none")
            .attr("stroke", d => d.severity === "critical" ? "#ff2727" : "#ff8c00")
            .attr("stroke-width", 2)
            .attr("opacity", 0.65)
            .style("animation", d => `zombie-pulse ${d.severity === "critical" ? "1.6" : "2.2"}s ease-out infinite`)
            .style("transform-origin", "center")
            .style("transform-box", "fill-box");

        // Middle ring for all active zombies
        nodeGroups.filter(d => d.classification === "active_zombie")
            .append("circle")
            .attr("r", d => nodeRadius(d) + 18)
            .attr("fill", "none")
            .attr("stroke", d => d.severity === "critical" ? "#ff2727" : "#ff8c00")
            .attr("stroke-width", 1.5)
            .attr("opacity", 0.35)
            .style("animation", d => `zombie-pulse ${d.severity === "critical" ? "1.6" : "2.2"}s ease-out 0.5s infinite`)
            .style("transform-origin", "center")
            .style("transform-box", "fill-box");

        // Outer ring for critical only
        nodeGroups.filter(d => d.classification === "active_zombie" && d.severity === "critical")
            .append("circle")
            .attr("r", d => nodeRadius(d) + 30)
            .attr("fill", "none")
            .attr("stroke", "#ff2727")
            .attr("stroke-width", 1)
            .attr("opacity", 0.18)
            .style("animation", "zombie-pulse 1.6s ease-out 1s infinite")
            .style("transform-origin", "center")
            .style("transform-box", "fill-box");

        // Main node circle
        nodeGroups.append("circle")
            .attr("class", "node-body")
            .attr("r", d => nodeRadius(d))
            .attr("fill", d => nodeFill(d))
            .attr("stroke", d => nodeStroke(d))
            .attr("stroke-width", d => nodeStrokeWidth(d))
            .attr("stroke-dasharray", d =>
                d.classification === "shadow"   ? "4,3" :
                d.classification === "orphaned" ? "2,4" : "none"
            );

        // PII badge
        nodeGroups.filter(d => d.is_pii && d.type !== "gateway")
            .append("circle")
            .attr("r", 5)
            .attr("cx", d => nodeRadius(d) - 3)
            .attr("cy", d => -(nodeRadius(d) - 3))
            .attr("fill", "#ff2727")
            .attr("stroke", "#080808")
            .attr("stroke-width", 1);
        nodeGroups.filter(d => d.is_pii && d.type !== "gateway")
            .append("text")
            .attr("x", d => nodeRadius(d) - 3)
            .attr("y", d => -(nodeRadius(d) - 3))
            .attr("text-anchor", "middle")
            .attr("dominant-baseline", "central")
            .attr("font-size", "7px")
            .attr("font-weight", "bold")
            .attr("fill", "white")
            .attr("pointer-events", "none")
            .text("!");

        // "GW" text inside gateway node
        nodeGroups.filter(d => d.type === "gateway")
            .append("text")
            .attr("text-anchor", "middle")
            .attr("dominant-baseline", "central")
            .attr("font-size", "11px")
            .attr("font-family", "'JetBrains Mono', monospace")
            .attr("font-weight", "900")
            .attr("fill", "#a855f7")
            .attr("pointer-events", "none")
            .text("GW");

        // Labels below nodes
        nodeGroups.append("text")
            .attr("text-anchor", "middle")
            .attr("y", d => nodeRadius(d) + 15)
            .attr("font-size", "10px")
            .attr("font-family", "'JetBrains Mono', monospace")
            .attr("fill", d => {
                if (d.type === "gateway") return "#a855f7";
                switch (d.classification) {
                    case "active_zombie":  return d.severity === "critical" ? "#ff2727" : "#ff8c00";
                    case "dormant_zombie": return "#666666";
                    case "shadow":         return "#4080ff";
                    case "drifting":       return "#f59e0b";
                    case "orphaned":       return "#c026d3";
                    default:               return "#22c55e";
                }
            })
            .attr("font-weight", d => (d.classification === "active_zombie" || d.type === "gateway") ? "700" : "400")
            .attr("pointer-events", "none")
            .text(d => {
                const l = d.label || d.id;
                const parts = l.split("/").filter(Boolean);
                return parts.length > 2 ? `…/${parts.slice(-2).join("/")}` : l.length > 24 ? l.slice(0, 22) + "…" : l;
            });

        // Tooltip
        let tip = el.querySelector<HTMLDivElement>(".ng-tooltip");
        if (!tip) {
            tip = document.createElement("div");
            tip.className = "ng-tooltip";
            tip.style.cssText = `
                opacity:0; pointer-events:none; position:absolute; z-index:100;
                background:#101010; border:1px solid #272727; border-radius:0;
                padding:10px 14px; min-width:180px; max-width:240px;
                font-family:'JetBrains Mono',monospace; font-size:11px;
                transition:opacity 0.1s;
            `;
            el.style.position = "relative";
            el.appendChild(tip);
        }
        const tooltip = tip;

        nodeGroups
            .on("mouseover", function(ev: MouseEvent, d: GraphNode) {
                const r = el.getBoundingClientRect();
                tooltip.style.left = `${ev.clientX - r.left + 16}px`;
                tooltip.style.top  = `${ev.clientY - r.top  - 16}px`;
                tooltip.style.opacity = "1";
                const clsColor = d.classification === "active_zombie"
                    ? (d.severity === "critical" ? "#ff2727" : "#ff8c00")
                    : d.classification === "dormant_zombie" ? "#444444"
                    : d.classification === "shadow"   ? "#4080ff"
                    : d.classification === "drifting" ? "#f59e0b"
                    : d.classification === "orphaned" ? "#c026d3"
                    : d.type === "gateway" ? "#a855f7" : "#22c55e";
                tooltip.innerHTML = `
                    <div style="font-size:11px;font-weight:600;color:#f0efea;margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid #1a1a1a;font-family:'JetBrains Mono',monospace;word-break:break-all">${d.label || d.id}</div>
                    <div style="display:flex;justify-content:space-between;gap:12px;font-size:10px;color:#444444;padding:2px 0"><span>class</span><span style="color:${clsColor}">${d.classification ?? "healthy"}</span></div>
                    <div style="display:flex;justify-content:space-between;gap:12px;font-size:10px;color:#444444;padding:2px 0"><span>severity</span><span style="color:#888888">${d.severity ?? "—"}</span></div>
                    <div style="display:flex;justify-content:space-between;gap:12px;font-size:10px;color:#444444;padding:2px 0"><span>ph_score</span><span style="color:#f0efea">${d.ph_score.toFixed(2)}</span></div>
                    <div style="display:flex;justify-content:space-between;gap:12px;font-size:10px;color:#444444;padding:2px 0"><span>traffic</span><span style="color:#f0efea">${d.traffic} req</span></div>
                    ${d.is_pii ? '<div style="display:flex;justify-content:space-between;gap:12px;font-size:10px;padding:2px 0"><span style="color:#444444">pii</span><span style="color:#ff2727">EXPOSED</span></div>' : ""}
                    ${d.dormant ? '<div style="display:flex;justify-content:space-between;gap:12px;font-size:10px;padding:2px 0"><span style="color:#444444">status</span><span style="color:#888888">DORMANT</span></div>' : ""}
                `;
                d3.select(this).select("circle.node-body").attr("stroke-width", d.type === "gateway" ? 3 : 2);
            })
            .on("mousemove", function(ev: MouseEvent) {
                const r = el.getBoundingClientRect();
                let x = ev.clientX - r.left + 16;
                let y = ev.clientY - r.top  - 16;
                if (x + 250 > r.width) x = ev.clientX - r.left - 256;
                tooltip.style.left = `${x}px`;
                tooltip.style.top  = `${y}px`;
            })
            .on("mouseout", function(_: MouseEvent, d: GraphNode) {
                tooltip.style.opacity = "0";
                d3.select(this).select("circle.node-body").attr("stroke-width", nodeStrokeWidth(d));
            })
            .on("click", function(_: MouseEvent, d: GraphNode) {
                if (d.type !== "gateway") onClickRef.current(d);
            });

        // Selection ring
        const applySelection = () => {
            nodeGroups.selectAll("circle.sel-ring").remove();
            if (!selectedRef.current) return;
            nodeGroups.filter(d => d.id === selectedRef.current)
                .append("circle")
                .attr("class", "sel-ring")
                .attr("r", d => nodeRadius(d) + 9)
                .attr("fill", "none")
                .attr("stroke", "#c8ff47")
                .attr("stroke-width", 1.5)
                .attr("stroke-dasharray", "6,3")
                .attr("opacity", 0.9);
        };
        applySelection();

        // Drag
        nodeGroups.call(
            d3.drag<SVGGElement, GraphNode>()
                .on("start", (ev, d) => {
                    if (!ev.active && simRef.current) simRef.current.alphaTarget(0.3).restart();
                    d.fx = d.x; d.fy = d.y;
                })
                .on("drag",  (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
                .on("end",   (ev, d) => {
                    if (!ev.active && simRef.current) simRef.current.alphaTarget(0);
                    if (d.type !== "gateway") { d.fx = null; d.fy = null; }
                })
        );

        // Force simulation
        const sim = d3.forceSimulation<GraphNode>(simNodes)
            .force("link",    d3.forceLink<GraphNode, GraphEdge>(simEdges).id(d => d.id).distance(100).strength(0.7))
            .force("charge",  d3.forceManyBody<GraphNode>().strength(-320).distanceMax(400))
            .force("collide", d3.forceCollide<GraphNode>().radius(d => nodeRadius(d) + 18).strength(0.9))
            .force("x",       d3.forceX<GraphNode>(W / 2).strength(0.04))
            .force("y",       d3.forceY<GraphNode>(H / 2).strength(0.04))
            .alpha(0.8)
            .alphaDecay(0.025);

        simRef.current = sim;

        sim.on("tick", () => {
            linkSel.each(function(d) {
                const src = d.source as unknown as GraphNode;
                const tgt = d.target as unknown as GraphNode;
                const sx = src.x ?? 0, sy = src.y ?? 0;
                const tx = tgt.x ?? 0, ty = tgt.y ?? 0;
                const dx = tx - sx, dy = ty - sy;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                // Shorten line by target radius + arrow head offset so marker sits on node edge
                const tr = nodeRadius(tgt) + 8;
                const sr = nodeRadius(src) + 2;
                d3.select(this)
                    .attr("x1", sx + (dx / dist) * sr)
                    .attr("y1", sy + (dy / dist) * sr)
                    .attr("x2", tx - (dx / dist) * tr)
                    .attr("y2", ty - (dy / dist) * tr);
            });
            nodeGroups.attr("transform", d => `translate(${d.x ?? 0},${d.y ?? 0})`);
        });

    }, []); // eslint-disable-line react-hooks/exhaustive-deps

    // ── Main rebuild effect ─────────────────────────────────────────────────────
    // Computes a lightweight content digest and only triggers a full D3 rebuild
    // when node or edge data actually changes. This prevents the simulation from
    // restarting on every 5-second poll when the API returns identical data
    // (which always produces new array references via useMemo in the parent).
    useEffect(() => {
        const digest =
            nodes.map(n =>
                `${n.id}:${n.classification ?? ""}:${n.severity ?? ""}:${n.is_pii ? 1 : 0}:${Math.round(n.ph_score * 10)}:${n.dormant ? 1 : 0}:${n.traffic}`
            ).join("|")
            + ">"
            + edges.map(e => `${e.source}->${e.target}`).join(",");

        if (digest === digestRef.current) return; // data unchanged — keep simulation running
        digestRef.current = digest;
        buildGraph();
        return () => { if (simRef.current) { simRef.current.stop(); simRef.current = null; } };
    }, [nodes, edges, buildGraph]);

    // ── Selection ring update — no full rebuild needed ──────────────────────────
    useEffect(() => {
        const svgEl = svgRef.current;
        if (!svgEl) return;
        const s = d3.select(svgEl);
        s.selectAll("circle.sel-ring").remove();
        if (selectedNodeId) {
            s.selectAll<SVGGElement, GraphNode>("g.node")
                .filter(d => d.id === selectedNodeId)
                .append("circle")
                .attr("class", "sel-ring")
                .attr("r", d => nodeRadius(d) + 9)
                .attr("fill", "none")
                .attr("stroke", "#c8ff47")
                .attr("stroke-width", 1.5)
                .attr("stroke-dasharray", "6,3")
                .attr("opacity", 0.9);
        }
    }, [selectedNodeId]);

    // ── Rebuild on container resize ─────────────────────────────────────────────
    useEffect(() => {
        const el = containerRef.current;
        if (!el) return;
        // Clear digest on resize so the next rebuild uses fresh dimensions
        const obs = new ResizeObserver(() => { digestRef.current = ""; buildGraph(); });
        obs.observe(el);
        return () => obs.disconnect();
    }, [buildGraph]);

    const isEmpty = nodes.length === 0;

    function handleReset() {
        digestRef.current = "";
        buildGraph();
    }

    return (
        <div ref={containerRef} style={{ flex: 1, width: "100%", height: "100%", minHeight: 420, position: "relative", background: "#080808" }}>
            {!isEmpty && (
                <button
                    onClick={handleReset}
                    title="Reset graph layout"
                    style={{
                        position: "absolute", top: 8, right: 8, zIndex: 10,
                        background: "rgba(8,8,8,0.85)", border: "1px solid #272727",
                        color: "#555555", fontSize: "13px", lineHeight: 1,
                        padding: "4px 7px", cursor: "pointer", fontFamily: "monospace",
                        transition: "color 0.12s, border-color 0.12s",
                    }}
                    onMouseEnter={e => { const b = e.currentTarget; b.style.color = "#f0efea"; b.style.borderColor = "#555"; }}
                    onMouseLeave={e => { const b = e.currentTarget; b.style.color = "#555555"; b.style.borderColor = "#272727"; }}
                >
                    ↺
                </button>
            )}
            {isEmpty ? (
                <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: "12px" }}>
                    <svg style={{ position: "absolute", inset: 0, opacity: 0.4, pointerEvents: "none" }} width="100%" height="100%">
                        <defs>
                            <pattern id="grid-empty" width="40" height="40" patternUnits="userSpaceOnUse">
                                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1a1a1a" strokeWidth="0.5" />
                            </pattern>
                        </defs>
                        <rect width="100%" height="100%" fill="url(#grid-empty)" />
                    </svg>
                    <span style={{ position: "relative", zIndex: 1, fontFamily: "'JetBrains Mono', monospace", fontSize: "12px", color: "#444444" }}>
                        // awaiting sensor data
                    </span>
                </div>
            ) : (
                <svg ref={svgRef} style={{ width: "100%", height: "100%", display: "block" }} />
            )}
        </div>
    );
}
