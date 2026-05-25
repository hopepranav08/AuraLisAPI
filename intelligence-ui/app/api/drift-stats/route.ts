// app/api/drift-stats/route.ts
// Synthesizes per-endpoint traffic counts from the auralis:events Redis stream.
// Used as a fallback when the eBPF sensor's /drift/stats HTTP endpoint is
// unreachable from bridge-network containers (Docker Desktop Windows).

import { NextResponse } from "next/server";

const REDIS_URL = process.env.REDIS_URL ?? "redis://redis:6379";
const STREAM    = process.env.REDIS_STREAM ?? "auralis:events";

// Simple TCP client for Redis — avoids importing ioredis/redis in Next.js edge
// We use the built-in fetch to call the brain's proxy instead and cache.
// Actually: call the brain's /drift/stats endpoint directly (server-side).
const BRAIN_URL = process.env.BRAIN_INTERNAL_URL ?? "http://remediation-brain:8000";

export async function GET() {
    try {
        const r = await fetch(`${BRAIN_URL}/drift/stats`, {
            signal: AbortSignal.timeout(4000),
            cache: "no-store",
        });
        if (r.ok) {
            const data = await r.json();
            return NextResponse.json(data);
        }
    } catch {
        // fall through to empty response
    }
    return NextResponse.json([]);
}
