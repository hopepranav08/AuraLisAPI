import type { NextConfig } from "next";

const nextConfig: NextConfig = {
    output: "standalone",

    // Skip ESLint during `next build` — run it separately via `npm run lint`.
    // Required for Docker builds where ESLint 9 flat-config resolution can fail
    // when there is no eslint.config.js / .eslintrc in the project root.
    eslint: {
        ignoreDuringBuilds: true,
    },

    async rewrites() {
        const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
        const brainUrl = process.env.BRAIN_INTERNAL_URL ?? "http://remediation-brain:8000";
        const sensorUrl = process.env.SENSOR_METRICS_URL ?? "http://host.docker.internal:9090";
        return [
            { source: "/api/:path*", destination: `${apiUrl}/api/:path*` },
            { source: "/brain/:path*", destination: `${brainUrl}/:path*` },
            { source: "/drift/:path*", destination: `${sensorUrl}/:path*` },
        ];
    },
};

export default nextConfig;
