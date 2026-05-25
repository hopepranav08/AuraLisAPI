import type { NextConfig } from "next";

// ── Public URL strategy ────────────────────────────────────────────────────────
//
// Two routing modes depending on deployment:
//
//  Docker Compose (default):
//    Browser fetches use relative paths (/brain/*, /drift/*) which the
//    Next.js dev server or standalone server proxies via rewrites() below.
//    NEXT_PUBLIC_BRAIN_URL and NEXT_PUBLIC_SENSOR_URL are left empty.
//
//  Standalone / CDN deployment:
//    Set NEXT_PUBLIC_BRAIN_URL=https://brain.yourapp.com and
//    NEXT_PUBLIC_SENSOR_URL=https://sensor.yourapp.com so the browser
//    calls those origins directly instead of going through rewrites.
//    Also set NEXT_PUBLIC_API_URL=https://api.yourapp.com.
//
// IMPORTANT: NEXT_PUBLIC_* vars are baked into the JS bundle at `next build`
// time.  In Docker Compose these are passed as build-time environment variables
// via the compose environment: section (set before running `docker-compose build`).

const nextConfig: NextConfig = {
    output: "standalone",

    eslint: {
        ignoreDuringBuilds: true,
    },

    // Expose public URL env vars to the browser bundle.
    // Defaults to empty string so UI falls back to rewrite-relative paths.
    env: {
        NEXT_PUBLIC_BRAIN_URL:  process.env.NEXT_PUBLIC_BRAIN_URL  ?? "",
        NEXT_PUBLIC_SENSOR_URL: process.env.NEXT_PUBLIC_SENSOR_URL ?? "",
        NEXT_PUBLIC_API_URL:    process.env.NEXT_PUBLIC_API_URL    ?? "",
    },

    async rewrites() {
        // Server-side runtime vars — available in Next.js standalone at runtime,
        // not baked into the bundle.  Used only for the rewrite() destination.
        const apiUrl   = process.env.API_INTERNAL_URL   ?? "http://api-gateway:8080";
        const brainUrl = process.env.BRAIN_INTERNAL_URL ?? "http://remediation-brain:8000";

        // /drift/* routes through the brain because the eBPF sensor uses
        // network_mode: host and is unreachable from bridge-network containers
        // on Docker Desktop.  The brain proxies to host.docker.internal:9090.
        return [
            { source: "/api/:path*",   destination: `${apiUrl}/api/:path*`    },
            { source: "/brain/:path*", destination: `${brainUrl}/:path*`       },
            { source: "/drift/:path*", destination: `${brainUrl}/drift/:path*` },
        ];
    },
};

export default nextConfig;
