# syntax=docker/dockerfile:1
# intelligence-ui — Next.js 15 Multi-stage Dockerfile
#
# Stage 1 (deps):    install node_modules
# Stage 2 (builder): compile Next.js app with output: 'standalone'
# Stage 3 (runner):  minimal production image using standalone output
#
# NOTE: We use `npm install` (not `npm ci` / `--frozen-lockfile`) because
# package-lock.json is gitignored. For a reproducible CI build, commit
# package-lock.json and switch to `npm ci`.

# ── Stage 1: Dependencies ─────────────────────────────────────────────────────
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json ./
RUN npm install

# ── Stage 2: Builder ──────────────────────────────────────────────────────────
FROM node:22-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1
# next.config.ts must have `output: 'standalone'` for Stage 3 to work
RUN npm run build

# ── Stage 3: Production runner ────────────────────────────────────────────────
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy standalone server output (includes all required node_modules inline)
RUN mkdir -p ./public
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["node", "server.js"]
