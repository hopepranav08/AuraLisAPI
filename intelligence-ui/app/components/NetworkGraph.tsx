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
    if (d.type === "gateway") return 22;
    const base = Math.max(12, Math.min(24, 12 + (d.traffic / 10)));
    return base;
}

function nodeColor(d: GraphNode): string {
    if (d.type === "gateway") return "#c084fc";          // violet — gateway
    switch (d.classification) {
        case "active_zombie":
            return d.severity === "critical" ? "#fb7185" : "#fbbf24";
        case "dormant_zombie":
            return "#3f3f46";
        case "shadow":
            return "#f472b6";                            // hot pink
        case "unknown":
            return "#38bdf8";                            // sky cyan
        default:
            return "#4ade80";                            // lime green — healthy
    }
}

function nodeGlowColor(d: GraphNode): string {
    if (d.type === "gateway") return "#c084fc";
    switch (d.classification) {
        case "active_zombie":
            return d.severity === "critical" ? "#fb7185" : "#fbbf24";
        case "shadow":
            return "#f472b6";
        case "unknown":
            return "#38bdf8";
        default:
            return "#4ade80";
    }
}

function edgeColor(d: GraphEdge, nodeMap: Map<string, GraphNode>): string {
    const targetId = typeof d.target === "object" ? (d.target as GraphNode).id : d.target;
    const target = nodeMap.get(targetId);
    if (!target) return "rgba(255,255,255,0.06)";
    if (target.classification === "active_zombie") return "rgba(251,113,133,0.35)";
    if (target.classification === "shadow") return "rgba(244,114,182,0.3)";
    if (target.classification === "unknown") return "rgba(56,189,248,0.25)";
    if (target.type === "gateway") return "rgba(192,132,252,0.2)";
    return "rgba(74,222,128,0.15)";
}

export default function NetworkGraph({ nodes, edges, onNodeClick, selectedNodeId }: Props) {
    const svgRef = useRef<SVGSVGElement>(null);
    const simulationRef = useRef<d3.Simulation<GraphNode, GraphEdge> | null>(null);
    const containerRef = useRef<HTMLDivElement>(null);
    const onNodeClickRef = useRef(onNodeClick);
    const selectedNodeIdRef = useRef(selectedNodeId);

    // Keep refs in sync so effect closures don't stale-close over callbacks
    useEffect(() => { onNodeClickRef.current = onNodeClick; }, [onNodeClick]);
    useEffect(() => { selectedNodeIdRef.current = selectedNodeId; }, [selectedNodeId]);

    const buildGraph = useCallback(() => {
        const svgEl = svgRef.current;
        const containerEl = containerRef.current;
        if (!svgEl || !containerEl) return;

        // Stop any running simulation
        if (simulationRef.current) {
            simulationRef.current.stop();
            simulationRef.current = null;
        }

        // Clear all SVG children
        d3.select(svgEl).selectAll("*").remove();

        const width = containerEl.clientWidth || 800;
        const height = containerEl.clientHeight || 460;

        if (nodes.length === 0) return; // empty state handled by JSX

        // Build node map for edge coloring lookups
        const nodeMap = new Map<string, GraphNode>(nodes.map(n => [n.id, n]));

        // Deep-clone node and edge arrays to avoid D3 mutating the React state
        const simNodes: GraphNode[] = nodes.map(n => ({ ...n }));
        const simEdges: GraphEdge[] = edges.map(e => ({ ...e }));

        // ── SVG setup ────────────────────────────────────────────────────────

        const svg = d3.select(svgEl)
            .attr("width", width)
            .attr("height", height);

        // ── Defs ─────────────────────────────────────────────────────────────

        const defs = svg.append("defs");

        // Radial gradients for nodes — glassmorphism poppy palette
        const gradients: Record<string, [string, string]> = {
            "grad-gateway":       ["#c084fc", "#3b0764"],   // bright violet
            "grad-zombie-crit":   ["#fb7185", "#4c0519"],   // bright rose red
            "grad-zombie-high":   ["#fbbf24", "#451a03"],   // amber gold
            "grad-dormant":       ["#52525b", "#18181b"],   // near-black grey
            "grad-shadow":        ["#f472b6", "#500724"],   // hot pink
            "grad-unknown":       ["#38bdf8", "#082f49"],   // sky cyan
            "grad-default":       ["#4ade80", "#052e16"],   // lime green
        };

        Object.entries(gradients).forEach(([id, [c1, c2]]) => {
            const grad = defs.append("radialGradient")
                .attr("id", id)
                .attr("cx", "35%").attr("cy", "35%")
                .attr("r", "65%");
            grad.append("stop").attr("offset", "0%").attr("stop-color", c1);
            grad.append("stop").attr("offset", "100%").attr("stop-color", c2);
        });

        // Glow filters — matched to poppy palette
        ["glow-red", "glow-violet", "glow-yellow", "glow-blue", "glow-pink", "glow-green"].forEach((id) => {
            const filter = defs.append("filter")
                .attr("id", id)
                .attr("x", "-50%").attr("y", "-50%")
                .attr("width", "200%").attr("height", "200%");
            filter.append("feGaussianBlur")
                .attr("in", "SourceGraphic")
                .attr("stdDeviation", "4")
                .attr("result", "blur");
            const merge = filter.append("feMerge");
            merge.append("feMergeNode").attr("in", "blur");
            merge.append("feMergeNode").attr("in", "blur");
            merge.append("feMergeNode").attr("in", "SourceGraphic");
        });

        // ── Zoom/pan container ───────────────────────────────────────────────

        const zoomG = svg.append("g").attr("class", "zoom-container");

        const zoom = d3.zoom<SVGSVGElement, unknown>()
            .scaleExtent([0.3, 4])
            .on("zoom", (event) => {
                zoomG.attr("transform", event.transform);
            });

        svg.call(zoom);

        // ── Links ─────────────────────────────────────────────────────────────

        const linkG = zoomG.append("g").attr("class", "links");

        const link = linkG.selectAll<SVGLineElement, GraphEdge>("line")
            .data(simEdges)
            .join("line")
            .attr("stroke-width", 1.5)
            .attr("stroke-opacity", 0.6)
            .attr("stroke", (d) => edgeColor(d, nodeMap));

        // ── Nodes ─────────────────────────────────────────────────────────────

        const nodeG = zoomG.append("g").attr("class", "nodes");

        const nodeGroups = nodeG.selectAll<SVGGElement, GraphNode>("g.node-group")
            .data(simNodes, (d) => d.id)
            .join("g")
            .attr("class", "node-group")
            .style("cursor", "pointer");

        // Pulse rings for zombie nodes (rendered behind the node fill)
        nodeGroups.filter((d) => d.classification === "active_zombie")
            .append("circle")
            .attr("class", (d) => d.severity === "critical" ? "pulse-ring" : "pulse-ring pulse-ring--warning")
            .attr("r", (d) => nodeRadius(d))
            .attr("fill", "none")
            .attr("stroke", (d) => d.severity === "critical" ? "#ef4444" : "#f97316")
            .attr("stroke-width", 2)
            .attr("opacity", 0.6)
            .style("animation", (d) =>
                d.severity === "critical"
                    ? "zombie-pulse-critical 2s ease-out infinite"
                    : "zombie-pulse-warning 2.5s ease-out infinite"
            )
            .style("transform-origin", "center")
            .style("transform-box", "fill-box");

        // Second ring for extra drama on critical
        nodeGroups.filter((d) => d.classification === "active_zombie" && d.severity === "critical")
            .append("circle")
            .attr("r", (d) => nodeRadius(d))
            .attr("fill", "none")
            .attr("stroke", "#ef4444")
            .attr("stroke-width", 1.5)
            .attr("opacity", 0.4)
            .style("animation", "zombie-pulse-critical 2s ease-out 1s infinite")
            .style("transform-origin", "center")
            .style("transform-box", "fill-box");

        // Node fill circle
        nodeGroups.append("circle")
            .attr("class", "node-fill")
            .attr("r", (d) => nodeRadius(d))
            .attr("fill", (d) => {
                if (d.type === "gateway") return "url(#grad-gateway)";
                switch (d.classification) {
                    case "active_zombie":
                        return d.severity === "critical" ? "url(#grad-zombie-crit)" : "url(#grad-zombie-high)";
                    case "dormant_zombie":
                        return "url(#grad-dormant)";
                    case "shadow":
                        return "url(#grad-shadow)";
                    case "unknown":
                        return "url(#grad-unknown)";
                    default:
                        return "url(#grad-default)";
                }
            })
            .attr("stroke", (d) => nodeColor(d))
            .attr("stroke-width", (d) => {
                if (d.type === "gateway") return 3;
                if (d.classification === "shadow") return 2;
                return 1.5;
            })
            .attr("stroke-dasharray", (d) => d.classification === "shadow" ? "4,3" : "none")
            .attr("filter", (d) => {
                const gc = nodeGlowColor(d);
                if (gc === "#fb7185") return "url(#glow-red)";
                if (gc === "#c084fc") return "url(#glow-violet)";
                if (gc === "#fbbf24") return "url(#glow-yellow)";
                if (gc === "#38bdf8") return "url(#glow-blue)";
                if (gc === "#f472b6") return "url(#glow-pink)";
                if (gc === "#4ade80") return "url(#glow-green)";
                return null;
            });

        // PII badge
        nodeGroups.filter((d) => d.is_pii && d.type !== "gateway")
            .append("circle")
            .attr("r", 6)
            .attr("cx", (d) => nodeRadius(d) - 4)
            .attr("cy", (d) => -(nodeRadius(d) - 4))
            .attr("fill", "#ef4444")
            .attr("stroke", "#080808")
            .attr("stroke-width", 1.5);

        nodeGroups.filter((d) => d.is_pii && d.type !== "gateway")
            .append("text")
            .attr("x", (d) => nodeRadius(d) - 4)
            .attr("y", (d) => -(nodeRadius(d) - 4))
            .attr("text-anchor", "middle")
            .attr("dominant-baseline", "central")
            .attr("font-size", "7px")
            .attr("font-weight", "bold")
            .attr("fill", "white")
            .attr("pointer-events", "none")
            .text("!");

        // Node label
        nodeGroups.append("text")
            .attr("text-anchor", "middle")
            .attr("dominant-baseline", "central")
            .attr("y", (d) => nodeRadius(d) + 13)
            .attr("font-size", (d) => d.type === "gateway" ? "10px" : "9px")
            .attr("font-family", "JetBrains Mono, monospace")
            .attr("fill", (d) => d.type === "gateway" ? "#c084fc" : "#71717a")
            .attr("pointer-events", "none")
            .text((d) => {
                const label = d.label || d.id;
                return label.length > 22 ? label.slice(0, 20) + "…" : label;
            });

        // ── Tooltip ──────────────────────────────────────────────────────────

        // Use a div tooltip absolutely positioned within the container
        let tooltipEl = containerEl.querySelector<HTMLDivElement>(".graph-tooltip");
        if (!tooltipEl) {
            tooltipEl = document.createElement("div");
            tooltipEl.className = "graph-tooltip";
            tooltipEl.style.opacity = "0";
            tooltipEl.style.pointerEvents = "none";
            tooltipEl.style.position = "absolute";
            containerEl.style.position = "relative";
            containerEl.appendChild(tooltipEl);
        }
        const tooltip = tooltipEl;

        nodeGroups
            .on("mouseover", function (event: MouseEvent, d: GraphNode) {
                const rect = containerEl.getBoundingClientRect();
                const x = event.clientX - rect.left + 12;
                const y = event.clientY - rect.top - 10;
                tooltip.style.left = `${x}px`;
                tooltip.style.top = `${y}px`;
                tooltip.style.opacity = "1";
                tooltip.innerHTML = `
                    <div class="graph-tooltip__title">${d.label || d.id}</div>
                    <div class="graph-tooltip__row"><span>Type</span><span>${d.type}</span></div>
                    <div class="graph-tooltip__row"><span>Class</span><span>${d.classification ?? "—"}</span></div>
                    <div class="graph-tooltip__row"><span>Severity</span><span>${d.severity ?? "—"}</span></div>
                    <div class="graph-tooltip__row"><span>PH Score</span><span>${d.ph_score.toFixed(2)}</span></div>
                    <div class="graph-tooltip__row"><span>Dormant</span><span>${d.dormant ? "Yes" : "No"}</span></div>
                    <div class="graph-tooltip__row"><span>PII</span><span>${d.is_pii ? "⚠ Yes" : "No"}</span></div>
                    <div class="graph-tooltip__row"><span>Traffic</span><span>${d.traffic}</span></div>
                `;
                // Highlight hovered node — target the fill circle specifically (not the pulse ring)
                d3.select(this).select("circle.node-fill").attr("stroke-width", 3);
            })
            .on("mousemove", function (event: MouseEvent) {
                const rect = containerEl.getBoundingClientRect();
                tooltip.style.left = `${event.clientX - rect.left + 12}px`;
                tooltip.style.top = `${event.clientY - rect.top - 10}px`;
            })
            .on("mouseout", function (_event: MouseEvent, d: GraphNode) {
                tooltip.style.opacity = "0";
                d3.select(this).select("circle.node-fill").attr("stroke-width", () => {
                    if (d.type === "gateway") return 3;
                    if (d.classification === "shadow") return 2;
                    return 1.5;
                });
            })
            .on("click", function (_event: MouseEvent, d: GraphNode) {
                onNodeClickRef.current(d);
            });

        // ── Selected node highlight ──────────────────────────────────────────

        function updateSelection() {
            nodeGroups.selectAll<SVGCircleElement, GraphNode>("circle.selection-ring").remove();
            if (!selectedNodeIdRef.current) return;
            nodeGroups.filter((d) => d.id === selectedNodeIdRef.current)
                .append("circle")
                .attr("class", "selection-ring")
                .attr("r", (d) => nodeRadius(d) + 6)
                .attr("fill", "none")
                .attr("stroke", "#c084fc")
                .attr("stroke-width", 2)
                .attr("stroke-dasharray", "4,2")
                .attr("opacity", 0.9);
        }

        updateSelection();

        // ── Drag ─────────────────────────────────────────────────────────────

        const drag = d3.drag<SVGGElement, GraphNode>()
            .on("start", (event, d) => {
                if (!event.active && simulationRef.current) {
                    simulationRef.current.alphaTarget(0.3).restart();
                }
                d.fx = d.x;
                d.fy = d.y;
            })
            .on("drag", (event, d) => {
                d.fx = event.x;
                d.fy = event.y;
            })
            .on("end", (event, d) => {
                if (!event.active && simulationRef.current) {
                    simulationRef.current.alphaTarget(0);
                }
                d.fx = null;
                d.fy = null;
            });

        nodeGroups.call(drag);

        // ── Simulation ───────────────────────────────────────────────────────

        const simulation = d3.forceSimulation<GraphNode>(simNodes)
            .force(
                "link",
                d3.forceLink<GraphNode, GraphEdge>(simEdges)
                    .id((d) => d.id)
                    .distance(90)
                    .strength(0.8)
            )
            .force("charge", d3.forceManyBody<GraphNode>().strength(-250))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collide", d3.forceCollide<GraphNode>().radius((d) => nodeRadius(d) + 14))
            .force("x", d3.forceX<GraphNode>(width / 2).strength(0.05))
            .force("y", d3.forceY<GraphNode>(height / 2).strength(0.05));

        simulationRef.current = simulation;

        const linkCoord = (n: string | number | GraphNode, axis: "x" | "y"): number => {
            if (typeof n === "object" && n !== null) return (n[axis] as number | undefined) ?? 0;
            return 0;
        };

        simulation.on("tick", () => {
            link
                .attr("x1", (d) => linkCoord(d.source, "x"))
                .attr("y1", (d) => linkCoord(d.source, "y"))
                .attr("x2", (d) => linkCoord(d.target, "x"))
                .attr("y2", (d) => linkCoord(d.target, "y"));

            nodeGroups.attr("transform", (d) => `translate(${d.x ?? 0},${d.y ?? 0})`);
        });

        // Re-apply selection ring whenever selectedNodeId updates
        // This is called by the parent re-render so we rely on useEffect deps

    }, [nodes, edges]); // eslint-disable-line react-hooks/exhaustive-deps

    // Rebuild when nodes/edges change
    useEffect(() => {
        buildGraph();
        return () => {
            if (simulationRef.current) {
                simulationRef.current.stop();
                simulationRef.current = null;
            }
        };
    }, [buildGraph]);

    // Update selection ring without rebuilding the whole graph
    useEffect(() => {
        const svgEl = svgRef.current;
        if (!svgEl) return;
        const svg = d3.select(svgEl);
        svg.selectAll<SVGCircleElement, GraphNode>("circle.selection-ring").remove();
        if (selectedNodeId) {
            svg.selectAll<SVGGElement, GraphNode>("g.node-group")
                .filter((d) => d.id === selectedNodeId)
                .append("circle")
                .attr("class", "selection-ring")
                .attr("r", (d) => nodeRadius(d) + 6)
                .attr("fill", "none")
                .attr("stroke", "#c084fc")
                .attr("stroke-width", 2)
                .attr("stroke-dasharray", "4,2")
                .attr("opacity", 0.9);
        }
    }, [selectedNodeId]);

    // ResizeObserver to rebuild on container size change
    useEffect(() => {
        const el = containerRef.current;
        if (!el) return;
        const observer = new ResizeObserver(() => {
            buildGraph();
        });
        observer.observe(el);
        return () => observer.disconnect();
    }, [buildGraph]);

    if (nodes.length === 0) {
        return (
            <div ref={containerRef} style={{ flex: 1, minHeight: 420, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <div className="graph-empty">
                    <div className="graph-empty__icon">
                        <svg width="24" height="24" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M9 3H5a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2V5a2 2 0 00-2-2h-4M9 3a2 2 0 002 2h2a2 2 0 002-2M9 3a2 2 0 012-2h2a2 2 0 012 2" />
                        </svg>
                    </div>
                    <span>Waiting for sensor data…</span>
                </div>
            </div>
        );
    }

    return (
        <div ref={containerRef} style={{ flex: 1, minHeight: 420, width: "100%", position: "relative" }}>
            <svg
                ref={svgRef}
                style={{ display: "block", width: "100%", height: "100%", minHeight: 420 }}
            />
        </div>
    );
}
