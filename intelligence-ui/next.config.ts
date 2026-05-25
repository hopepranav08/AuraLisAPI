import type { NextConfig } from "next";

const nextConfig: NextConfig = {
    output: "standalone",

    // Skip ESLint during `next build` — run it separately via `npm run lint`.
    eslint: {
        ignoreDuringBuilds: true,
    },

    async rewrites() {
        const apiUrl   = process.env.API_INTERNAL_URL   ?? "http://api-gateway:8080";
        const brainUrl = process.env.BRAIN_INTERNAL_URL ?? "http://remediation-brain:8000";

        // /drift/* routes through the brain (remediation-brain:8000/drift/*)
        // because the eBPF sensor uses network_mode: host and is unreachable
        // from bridge-network containers via host.docker.internal on Docker Desktop.
        // The brain has extra_hosts: host.docker.internal + a /drift/stats proxy endpoint.
        return [
            { source: "/api/:path*",   destination: `${apiUrl}/api/:path*`   },
            { source: "/brain/:path*", destination: `${brainUrl}/:path*`      },
            { source: "/drift/:path*", destination: `${brainUrl}/drift/:path*` },
        ];
    },
};

export default nextConfig;
