'use client';
import { useState, useEffect, useRef } from 'react';
import type { ReactNode } from 'react';
import Link from 'next/link';

// ── Palette (dark brutalism) ──────────────────────────────────────────────────
const C = {
  bg:   '#0c0c0c',
  s1:   '#111111',
  s2:   '#161616',
  b:    '#1e1e1e',
  b2:   '#2a2a2a',
  t1:   '#f0f0f0',
  t2:   '#888888',
  t3:   '#444444',
  lime: '#4afa7a',
  pink: '#ff2d78',
  cyan: '#00d4ff',
  purp: '#a855f7',
} as const;

// ── Terminal ──────────────────────────────────────────────────────────────────
const TERM_LINES = [
  { text: '$ curl -sSL auralisapi.dev/install.sh | bash', cls: 'cmd',    ms: 200  },
  { text: '✓  Docker found: 24.0.7',                      cls: 'ok',     ms: 900  },
  { text: '✓  Kernel 5.15 — eBPF supported',              cls: 'ok',     ms: 1500 },
  { text: '✓  Sensor started: acme-prod-01',              cls: 'ok',     ms: 2100 },
  { text: '',                                              cls: 'dim',    ms: 2600 },
  { text: '⚡ Scanning kernel network stack...',           cls: 'dim',    ms: 3000 },
  { text: '◉  ZOMBIE  /api/v1/users     PII:email,ssn',   cls: 'danger', ms: 3700 },
  { text: '◉  ZOMBIE  /api/v1/payments  PII:card,cvv',    cls: 'danger', ms: 4300 },
  { text: '◈  SHADOW  /legacy/export    [undocumented]',  cls: 'warn',   ms: 4900 },
  { text: '',                                              cls: 'dim',    ms: 5400 },
  { text: '▶  AI: Incident #1 → severity=critical',       cls: 'ai',     ms: 5800 },
  { text: '▶  AI: 410 Gone enforced on /api/v1/*',        cls: 'ai',     ms: 6700 },
  { text: '▶  AI: PR #247 created → GitHub',              cls: 'ai',     ms: 7500 },
  { text: '',                                              cls: 'dim',    ms: 8000 },
  { text: '✓  /api/v1/users    → 410 GONE',               cls: 'ok',     ms: 8400 },
  { text: '✓  /api/v1/payments → 410 GONE',               cls: 'ok',     ms: 8800 },
  { text: '✓  Honeypot live — attacker captured',         cls: 'ok',     ms: 9300 },
] as const;

type TCls = 'cmd' | 'ok' | 'dim' | 'danger' | 'warn' | 'ai';
const TC: Record<TCls, string> = {
  cmd:    C.lime,
  ok:     '#22c55e',
  dim:    '#333',
  danger: '#ff3b3b',
  warn:   '#ff9500',
  ai:     C.cyan,
};

function LiveTerminal() {
  const [lines, setLines] = useState<typeof TERM_LINES[number][]>([]);
  const cycle = useRef(0);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    cycle.current += 1;
    const k = cycle.current;
    const ids: ReturnType<typeof setTimeout>[] = [];
    TERM_LINES.forEach(l => {
      ids.push(setTimeout(() => {
        if (cycle.current !== k) return;
        setLines(p => [...p, l]);
        // Scroll only the terminal body, not the whole page
        const el = bodyRef.current;
        if (el) el.scrollTop = el.scrollHeight;
      }, l.ms));
    });
    ids.push(setTimeout(() => { if (cycle.current === k) setLines([]); }, 13000));
    return () => ids.forEach(clearTimeout);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lines.length === 0 ? cycle.current : 0]);

  return (
    <div style={{ background: '#080808', border: `1px solid ${C.b}`, borderTop: `3px solid ${C.lime}`, fontFamily: "'JetBrains Mono', monospace", fontSize: 12, width: '100%' }}>
      {/* Title bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '8px 14px', background: '#0f0f0f', borderBottom: `1px solid ${C.b}` }}>
        <span style={{ color: '#ff5f57', fontSize: 9 }}>●</span>
        <span style={{ color: '#febc2e', fontSize: 9 }}>●</span>
        <span style={{ color: '#28c840', fontSize: 9 }}>●</span>
        <span style={{ marginLeft: 10, fontSize: 10, color: '#333', flex: 1 }}>auralis-sensor — bash</span>
        <span style={{ width: 7, height: 7, borderRadius: '50%', background: C.lime, animation: 'pulse-ok 1.5s infinite', display: 'inline-block' }} />
      </div>
      {/* Body */}
      <div ref={bodyRef} style={{ padding: '14px 16px', minHeight: 300, maxHeight: 340, overflowY: 'auto' }}>
        {lines.map((l, i) => (
          <div key={i} style={{ color: TC[l.cls as TCls] ?? '#555', lineHeight: 1.9 }}>
            {l.text || ' '}
          </div>
        ))}
        <span style={{ display: 'inline-block', width: 7, height: '1.1em', background: C.lime, verticalAlign: 'text-bottom', animation: 'blink 1s step-end infinite' }} />
      </div>
    </div>
  );
}

// ── Animated counter ──────────────────────────────────────────────────────────
function useCounter(target: number, dur = 1800) {
  const [val, setVal] = useState(0);
  const started = useRef(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    const obs = new IntersectionObserver(([e]) => {
      if (!e.isIntersecting || started.current) return;
      started.current = true;
      const t0 = performance.now();
      const run = (now: number) => {
        const p = Math.min((now - t0) / dur, 1);
        setVal(Math.round((1 - Math.pow(1 - p, 3)) * target));
        if (p < 1) requestAnimationFrame(run);
      };
      requestAnimationFrame(run);
    }, { threshold: 0.5 });
    obs.observe(node);
    return () => obs.disconnect();
  }, [target, dur]);
  return { val, ref };
}

// ── Scroll reveal ─────────────────────────────────────────────────────────────
function useReveal(delay = 0) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    const obs = new IntersectionObserver(([e]) => {
      if (!e.isIntersecting) return;
      setTimeout(() => node.classList.add('visible'), delay);
      obs.disconnect();
    }, { threshold: 0.06 });
    obs.observe(node);
    return () => obs.disconnect();
  }, [delay]);
  return ref;
}

// ── Glitch text (periodic auto-glitch + hover) ────────────────────────────────
function GlitchText({ children }: { children: string }) {
  const [active, setActive] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    const schedule = () => {
      timer.current = setTimeout(() => {
        setActive(true);
        setTimeout(() => { setActive(false); schedule(); }, 450);
      }, 2500 + Math.random() * 4000);
    };
    timer.current = setTimeout(schedule, 1200);
    return () => { if (timer.current) clearTimeout(timer.current); };
  }, []);
  return (
    <span
      className={`glitch${active ? ' active' : ''}`}
      data-text={children}
      onMouseEnter={() => setActive(true)}
      onMouseLeave={() => setActive(false)}
      style={{ color: C.lime }}
    >
      {children}
    </span>
  );
}

// ── Ticker content ────────────────────────────────────────────────────────────
const TICK = [
  'ZOMBIE API DETECTED', '/api/v1/users', 'PII EXPOSED — SSN + EMAIL',
  'DRIFT ALARM', '410 ENFORCED', 'SHADOW API', 'RESURRECTION EVENT',
  'HONEYPOT HIT', 'INCIDENT OPENED', 'BRAIN ACTIVATED', 'KRAKEND MUTATED',
  'PR CREATED — GITHUB', 'ATTACKER CAPTURED', 'ZERO-TRUST ENFORCED',
  'OWASP API9:2023 MITIGATED', 'eBPF TRACE CAPTURED',
].join('   ◈   ');

// ── Features ──────────────────────────────────────────────────────────────────
const FEATURES = [
  { icon: '⬡', title: 'eBPF Kernel Telemetry',  tech: 'Go + cilium/ebpf',      desc: 'Zero-overhead HTTP/HTTPS/TLS endpoint discovery at the Linux kernel network layer. No proxies, no code changes.' },
  { icon: '⬢', title: 'LangGraph AI Brain',      tech: 'Python + LangGraph',    desc: 'Stateful agentic pipeline: ingest → analyze → plan → enforce → report. Human-in-the-loop approval gate on all enforcements.' },
  { icon: '≈',  title: 'Page-Hinkley Drift',     tech: '10s windows · δ=0.005', desc: 'Statistical change-point detection in 10-second windows. Flags zombie endpoint resurrection after months of silence.' },
  { icon: '◈',  title: 'Dynamic Honeypots',      tech: 'FastAPI + Faker',        desc: 'Decoy endpoints mirror your deprecated API surface. Attackers receive convincing fake data while we capture full TTPs.' },
  { icon: '⊘',  title: 'Zero-Trust Enforcement', tech: 'KrakenD v3',            desc: '410 Gone enforced via gateway mutation in seconds of AI confirmation. No application code changes required.' },
  { icon: '⑂',  title: 'GitOps Audit Trail',     tech: 'GitHub API',            desc: 'Every enforcement creates a PR with a full AI-written incident report: affected paths, PII findings, root cause analysis.' },
];

// ── Threats ───────────────────────────────────────────────────────────────────
const THREATS = [
  { code: 'ACTIVE_ZOMBIE',  name: 'Active Zombie',  color: '#ff3b3b', bg: 'rgba(255,59,59,0.04)',   desc: 'Deprecated endpoints with sudden traffic bursts — classic attacker reconnaissance signature. Immediate enforcement.' },
  { code: 'DORMANT_ZOMBIE', name: 'Dormant Zombie', color: '#ff9500', bg: 'rgba(255,149,0,0.04)',   desc: 'Deprecated endpoints with traffic tapering to zero — primed for future exploitation. Scheduled for retirement.' },
  { code: 'SHADOW',         name: 'Shadow API',     color: C.cyan,    bg: 'rgba(0,212,255,0.04)',   desc: 'Undocumented paths absent from OpenAPI spec — internal routes, debug endpoints, untracked microservices.' },
  { code: 'PII_EXPOSED',    name: 'PII Exposure',   color: C.purp,    bg: 'rgba(168,85,247,0.04)', desc: 'Response bodies containing SSNs, credit card numbers, or passport data on deprecated or shadow paths.' },
];

// ── OWASP rows ────────────────────────────────────────────────────────────────
const OWASP = [
  { id: 'API9:2023', name: 'Improper Inventory Management',     sev: 'CRITICAL', color: '#ff3b3b' },
  { id: 'API1:2023', name: 'Broken Object Level Authorization', sev: 'HIGH',     color: '#ff9500' },
  { id: 'API4:2023', name: 'Unrestricted Resource Consumption', sev: 'HIGH',     color: '#ff9500' },
  { id: 'API5:2023', name: 'Broken Function Level Auth',        sev: 'HIGH',     color: '#ff9500' },
  { id: 'API6:2023', name: 'Sensitive Business Flow Abuse',     sev: 'MEDIUM',   color: C.cyan    },
];

// ── Main page ─────────────────────────────────────────────────────────────────
export default function LandingPage() {
  const [copied, setCopied] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [live, setLive] = useState<{ endpoints: number; zombies: number } | null>(null);

  const c0 = useCounter(10000);
  const c1 = useCounter(500);
  const c2 = useCounter(60);
  const c3 = useCounter(5);

  const rStats    = useReveal(0);
  const rHow      = useReveal(0);
  const rThreats  = useReveal(0);
  const rFeats    = useReveal(0);
  const rOwasp    = useReveal(0);
  const rInstall  = useReveal(0);
  const rCta      = useReveal(0);

  useEffect(() => {
    const h = () => setScrolled(window.scrollY > 30);
    window.addEventListener('scroll', h, { passive: true });
    return () => window.removeEventListener('scroll', h);
  }, []);

  useEffect(() => {
    const poll = async () => {
      try {
        const r = await fetch('/brain/inventory', { signal: AbortSignal.timeout(3000) });
        if (r.ok) { const d = await r.json(); setLive({ endpoints: d.total, zombies: d.zombies }); }
      } catch { /* offline */ }
    };
    poll();
    const id = setInterval(poll, 15000);
    return () => clearInterval(id);
  }, []);

  const copyInstall = () => {
    navigator.clipboard.writeText('curl -sSL https://install.auralisapi.dev | bash');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // ── Shared section header ──────────────────────────────────────────────────
  const SH = ({ tag, h, sub }: { tag: string; h: ReactNode; sub?: string }) => (
    <div style={{ marginBottom: 52 }}>
      <span style={{ display: 'block', fontSize: 10, fontWeight: 700, color: C.lime, letterSpacing: '0.18em', marginBottom: 14 }}>// {tag}</span>
      <h2 style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: 'clamp(28px, 4vw, 44px)', fontWeight: 800, color: C.t1, lineHeight: 1.1, letterSpacing: '-0.025em', marginBottom: sub ? 12 : 0 }}>{h}</h2>
      {sub && <p style={{ fontSize: 13, color: C.t2, marginTop: 10, lineHeight: 1.65 }}>{sub}</p>}
    </div>
  );

  return (
    <div style={{ background: C.bg, color: C.t1, fontFamily: "'JetBrains Mono', monospace", minHeight: '100vh', overflowX: 'hidden' }}>

      {/* ── Nav ── */}
      <nav style={{
        position: 'fixed', top: 0, left: 0, right: 0, zIndex: 300,
        height: 56, background: 'rgba(12,12,12,0.96)',
        borderBottom: `1px solid ${scrolled ? C.lime : C.b}`,
        backdropFilter: 'blur(16px)', WebkitBackdropFilter: 'blur(16px)',
        display: 'flex', alignItems: 'center', padding: '0 28px', gap: 8,
        transition: 'border-color 0.35s',
      }}>
        <Link href="/" style={{ textDecoration: 'none', marginRight: 8 }}>
          <span style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: 20, fontWeight: 800, color: C.lime, letterSpacing: '-0.01em' }}>AURALIS</span>
        </Link>
        <div style={{ flex: 1 }} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          {([
            { href: '/dashboard',              label: 'Dashboard'     },
            { href: '/dashboard/attack-arena', label: 'Attack Arena'  },
            { href: '/install',                label: 'Install'       },
          ] as const).map(l => (
            <Link key={l.href} href={l.href} style={{
              textDecoration: 'none', color: C.t2, fontSize: 11, fontWeight: 600,
              padding: '6px 14px', letterSpacing: '0.05em', textTransform: 'uppercase',
              transition: 'color 0.12s',
            }}
              onMouseEnter={e => { (e.currentTarget as HTMLAnchorElement).style.color = C.t1; }}
              onMouseLeave={e => { (e.currentTarget as HTMLAnchorElement).style.color = C.t2; }}
            >{l.label}</Link>
          ))}
          <div style={{ width: 1, height: 20, background: C.b, margin: '0 8px' }} />
          <Link href="/login" style={{ textDecoration: 'none' }}>
            <button style={{
              background: C.lime, color: C.bg,
              border: 'none', cursor: 'pointer',
              fontFamily: "'Space Grotesk', sans-serif", fontWeight: 800,
              fontSize: 11, padding: '7px 18px', letterSpacing: '0.07em',
              textTransform: 'uppercase',
              transition: 'background 0.12s, transform 0.1s',
            }}
              onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = '#6ffb9a'; }}
              onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = C.lime; }}
            >Login →</button>
          </Link>
        </div>
      </nav>

      {/* ── Ticker ── */}
      <div style={{ marginTop: 56, background: C.lime, height: 34, overflow: 'hidden', display: 'flex', alignItems: 'center' }}>
        <div style={{ display: 'flex', whiteSpace: 'nowrap', animation: 'ticker-scroll 50s linear infinite' }}>
          {[TICK, TICK].map((t, i) => (
            <span key={i} style={{ color: C.bg, fontWeight: 700, fontSize: 10, letterSpacing: '0.15em', padding: '0 56px' }}>{t}</span>
          ))}
        </div>
      </div>

      {/* ── Hero ── */}
      <section style={{
        minHeight: 'calc(100vh - 90px)',
        display: 'flex', alignItems: 'center',
        padding: '72px 28px 80px',
        position: 'relative',
        backgroundImage: `radial-gradient(${C.lime}0d 1px, transparent 1px)`,
        backgroundSize: '32px 32px',
        animation: 'grid-drift 14s linear infinite',
      }}>
        {/* radial vignette overlay */}
        <div style={{
          position: 'absolute', inset: 0, pointerEvents: 'none',
          background: `radial-gradient(ellipse 80% 80% at 50% 50%, transparent 30%, ${C.bg} 100%)`,
        }} />
        {/* bottom fade */}
        <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: 120, background: `linear-gradient(to bottom, transparent, ${C.bg})`, pointerEvents: 'none' }} />

        <div style={{ maxWidth: 1240, margin: '0 auto', width: '100%', position: 'relative', zIndex: 1 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 72, alignItems: 'center' }}>

            {/* Left copy */}
            <div>
              {/* Badge */}
              <div style={{ marginBottom: 28 }}>
                <span style={{
                  display: 'inline-flex', alignItems: 'center', gap: 7,
                  padding: '5px 14px', border: `1px solid ${C.lime}22`,
                  background: `${C.lime}08`,
                  color: C.lime, fontSize: 10, fontWeight: 700, letterSpacing: '0.12em',
                }}>
                  <span style={{ width: 5, height: 5, borderRadius: '50%', background: C.lime, animation: 'pulse-ok 1.5s infinite', display: 'inline-block' }} />
                  OWASP API9:2023 · ZOMBIE API KILLER
                </span>
              </div>

              {/* Headline */}
              <h1 style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: 'clamp(54px, 7.5vw, 88px)',
                fontWeight: 800, color: C.t1, lineHeight: 1.0,
                marginBottom: 24, letterSpacing: '-0.03em',
              }}>
                STOP<br />
                <GlitchText>ZOMBIE</GlitchText><br />
                <span style={{ color: C.t3 }}>APIs.</span>
              </h1>

              <p style={{ fontSize: 14, color: C.t2, maxWidth: 460, marginBottom: 38, lineHeight: 1.75 }}>
                {'// Autonomous zero-trust API governance via kernel-level eBPF telemetry + LangGraph AI. Detect, classify, enforce.'}
              </p>

              {/* CTAs */}
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 40 }}>
                <Link href="/install" style={{ textDecoration: 'none' }}>
                  <button className="lbtn-lime">Deploy Sensor →</button>
                </Link>
                <Link href="/dashboard" style={{ textDecoration: 'none' }}>
                  <button className="lbtn-ghost">[View Demo]</button>
                </Link>
                <Link href="/dashboard/attack-arena" style={{ textDecoration: 'none' }}>
                  <button className="lbtn-red">◈ Attack Arena</button>
                </Link>
              </div>

              {/* Live status */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 20 }}>
                {live ? (
                  <>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontSize: 11, color: C.t3 }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', animation: 'pulse-ok 2s infinite', display: 'inline-block' }} />
                      {live.endpoints} endpoints tracked
                    </span>
                    {live.zombies > 0 && (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontSize: 11, color: C.t3 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: C.pink, animation: 'pulse-red 2s infinite', display: 'inline-block' }} />
                        {live.zombies} zombie APIs detected
                      </span>
                    )}
                  </>
                ) : (
                  <span style={{ fontSize: 11, color: C.t3 }}>// kernel-level · zero-overhead · no code changes</span>
                )}
              </div>
            </div>

            {/* Right terminal */}
            <div style={{ animation: 'float-y 6s ease-in-out infinite' }}>
              <LiveTerminal />
              {/* Below terminal — tech tags */}
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 16 }}>
                {['Go + eBPF', 'LangGraph', 'KrakenD', 'Redis', 'PostgreSQL', 'GitHub API'].map(t => (
                  <span key={t} style={{
                    fontSize: 10, color: C.t3, border: `1px solid ${C.b2}`,
                    padding: '3px 9px', letterSpacing: '0.06em',
                  }}>{t}</span>
                ))}
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* ── Stats strip ── */}
      <section style={{ background: C.s1, borderTop: `1px solid ${C.b}`, borderBottom: `1px solid ${C.b}` }}>
        <div ref={rStats} className="reveal" style={{ maxWidth: 1240, margin: '0 auto', display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)' }}>
          {[
            { r: c0, suf: '+', lbl: 'Endpoints Detected',     col: C.lime },
            { r: c1, suf: '+', lbl: 'Zombies Quarantined',    col: C.pink },
            { r: c2, suf: 's', lbl: 'Mean Time to Enforce',   col: C.cyan },
            { r: c3, suf: '',  lbl: 'OWASP Threats Mitigated', col: C.purp },
          ].map((s, i) => (
            <div key={s.lbl} ref={s.r.ref} style={{
              padding: '44px 32px',
              borderRight: i < 3 ? `1px solid ${C.b}` : 'none',
              borderTop: `3px solid ${s.col}`,
              transition: 'background 0.18s',
            }}
              onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.background = C.s2; }}
              onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.background = ''; }}
            >
              <div style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: 'clamp(38px, 4vw, 56px)', fontWeight: 800,
                color: s.col, lineHeight: 1, marginBottom: 10,
              }}>
                {s.r.val.toLocaleString()}{s.suf}
              </div>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.t3, textTransform: 'uppercase', letterSpacing: '0.13em', fontFamily: "'Space Grotesk', sans-serif" }}>
                {s.lbl}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── How it works ── */}
      <section style={{ padding: '100px 28px', background: C.bg }}>
        <div ref={rHow} className="reveal" style={{ maxWidth: 1240, margin: '0 auto' }}>
          <SH tag="HOW IT WORKS" h={<>From install to enforcement<br /><span style={{ color: C.lime }}>in under 60 seconds.</span></>}
            sub="// No code changes. No OpenAPI spec. No instrumentation. Install and watch." />

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 0 }}>
            {[
              { n: '01', title: 'Install the sensor',  col: C.lime, code: '$ curl -sSL auralisapi.dev/install.sh | bash',  desc: 'One curl command deploys a 12MB Go binary. The eBPF sensor attaches to the kernel immediately, observing all HTTP/HTTPS/TLS traffic with zero overhead.' },
              { n: '02', title: 'Detect & classify',   col: C.cyan, code: 'ZOMBIE: /api/v1/users [PII: email, ssn]',        desc: 'Page-Hinkley drift detection classifies every endpoint: healthy, zombie, dormant, or shadow. PII entropy analysis flags exposed sensitive data.' },
              { n: '03', title: 'Remediate with AI',   col: C.pink, code: 'PR #247 → 410 enforced on /api/v1/*',            desc: 'LangGraph opens an incident, proposes enforcement, awaits human approval, enforces 410 Gone via KrakenD. Every change documented in a GitHub PR.' },
            ].map((s, i) => (
              <div key={i} className="step-card" style={{
                padding: '40px 36px',
                border: `1px solid ${C.b}`,
                borderLeft: i > 0 ? 'none' : `1px solid ${C.b}`,
                borderTop: `3px solid ${s.col}`,
                background: 'transparent',
              }}>
                <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: 64, fontWeight: 800, color: s.col, opacity: 0.15, lineHeight: 1, marginBottom: 24 }}>{s.n}</div>
                <h4 style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 700, fontSize: 17, color: C.t1, marginBottom: 12 }}>{s.title}</h4>
                <p style={{ color: C.t2, fontSize: 13, lineHeight: 1.7, marginBottom: 18 }}>{s.desc}</p>
                <div style={{ background: '#080808', borderLeft: `2px solid ${s.col}`, padding: '9px 13px', fontSize: 11, color: s.col, overflowX: 'auto', whiteSpace: 'nowrap' }}>
                  {s.code}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Threat detection ── */}
      <section style={{ padding: '100px 28px', background: C.s1, borderTop: `1px solid ${C.b}`, borderBottom: `1px solid ${C.b}` }}>
        <div ref={rThreats} className="reveal" style={{ maxWidth: 1240, margin: '0 auto' }}>
          <SH tag="THREAT DETECTION" h="What AuralisAPI hunts." />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 0 }}>
            {THREATS.map((t, i) => (
              <div key={t.code} className="threat-card" style={{
                padding: '32px 32px',
                background: t.bg,
                border: `1px solid ${C.b}`,
                borderLeft: `3px solid ${t.color}`,
                borderTop: i < 2 ? `1px solid ${C.b}` : 'none',
                borderRight: i % 2 === 0 ? 'none' : `1px solid ${C.b}`,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: t.color, border: `1px solid ${t.color}22`, padding: '2px 8px', letterSpacing: '0.08em', background: `${t.color}08` }}>{t.code}</span>
                </div>
                <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 700, fontSize: 17, color: t.color, marginBottom: 10 }}>{t.name}</div>
                <div style={{ fontSize: 13, color: C.t2, lineHeight: 1.7 }}>{t.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Features ── */}
      <section style={{ padding: '100px 28px', background: C.bg }}>
        <div ref={rFeats} className="reveal" style={{ maxWidth: 1240, margin: '0 auto' }}>
          <SH tag="CAPABILITIES" h="Six integrated capabilities." />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 0 }}>
            {FEATURES.map((f, i) => (
              <div key={f.title} className="feat-card" style={{
                padding: '32px 32px',
                border: `1px solid ${C.b}`,
                borderTop: i < 3 ? `1px solid ${C.b}` : 'none',
                borderLeft: i % 3 > 0 ? 'none' : `1px solid ${C.b}`,
              }}>
                <div style={{ fontSize: 30, marginBottom: 16, color: C.lime }}>{f.icon}</div>
                <h4 style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 700, fontSize: 14, color: C.t1, marginBottom: 10 }}>{f.title}</h4>
                <p style={{ color: C.t2, fontSize: 12, lineHeight: 1.7, marginBottom: 14 }}>{f.desc}</p>
                <span style={{ display: 'inline-block', fontSize: 10, color: C.t3, border: `1px solid ${C.b2}`, padding: '2px 9px', letterSpacing: '0.06em' }}>{f.tech}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── OWASP ── */}
      <section style={{ padding: '100px 28px', background: C.s1, borderTop: `1px solid ${C.b}` }}>
        <div ref={rOwasp} className="reveal" style={{ maxWidth: 1240, margin: '0 auto' }}>
          <SH tag="SECURITY COVERAGE" h="OWASP API Top 10 coverage." />
          <div style={{ border: `1px solid ${C.b}`, borderTop: `3px solid ${C.lime}`, overflow: 'hidden' }}>
            {/* Header row */}
            <div style={{ display: 'grid', gridTemplateColumns: '170px 1fr 110px', background: C.s2, borderBottom: `1px solid ${C.b}`, padding: '10px 20px', gap: 24 }}>
              {['OWASP ID', 'VULNERABILITY', 'SEVERITY'].map(h => (
                <span key={h} style={{ fontSize: 10, fontWeight: 700, color: C.t3, letterSpacing: '0.14em', fontFamily: "'Space Grotesk', sans-serif" }}>{h}</span>
              ))}
            </div>
            {OWASP.map((r, i) => (
              <div key={r.id} style={{
                display: 'grid', gridTemplateColumns: '170px 1fr 110px',
                padding: '16px 20px', gap: 24,
                borderBottom: i < OWASP.length - 1 ? `1px solid ${C.b}` : 'none',
                alignItems: 'center', transition: 'background 0.12s',
              }}
                onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.background = C.s2; }}
                onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.background = ''; }}
              >
                <span style={{ fontSize: 12, fontWeight: 700, color: r.color }}>{r.id}</span>
                <span style={{ fontSize: 13, color: C.t1 }}>{r.name}</span>
                <span style={{
                  display: 'inline-flex', alignItems: 'center',
                  padding: '3px 10px', border: `1px solid ${r.color}`,
                  color: r.color, fontSize: 10, fontWeight: 700, letterSpacing: '0.08em',
                  background: `${r.color}10`,
                }}>{r.sev}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Install ── */}
      <section style={{ padding: '100px 28px', background: C.bg, borderTop: `1px solid ${C.b}` }}>
        <div ref={rInstall} className="reveal" style={{ maxWidth: 720, margin: '0 auto', textAlign: 'center' }}>
          <SH tag="QUICK INSTALL" h="One command. 60 seconds to live."
            sub="// Works on any Linux server with Docker. Kernel ≥ 5.8 for live eBPF mode." />

          <div style={{ background: '#080808', border: `1px solid ${C.b}`, borderTop: `3px solid ${C.lime}`, boxShadow: `8px 8px 0 ${C.lime}18`, textAlign: 'left' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 16px', background: '#0f0f0f', borderBottom: `1px solid ${C.b}` }}>
              <span style={{ fontSize: 10, color: '#333' }}>// terminal</span>
              <button onClick={copyInstall} style={{
                background: copied ? `${C.lime}18` : 'transparent',
                border: `1px solid ${copied ? C.lime : C.b2}`,
                color: copied ? C.lime : '#555',
                fontSize: 10, padding: '3px 10px', cursor: 'pointer',
                fontFamily: "'JetBrains Mono', monospace",
                transition: 'all 0.15s',
              }}>
                {copied ? '✓ COPIED' : '⎘ COPY'}
              </button>
            </div>
            <div style={{ padding: '14px 16px', fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}>
              <span style={{ color: '#333' }}>$ </span>
              <span style={{ color: '#f0f0f0' }}>curl -sSL https://install.auralisapi.dev | bash</span>
            </div>
            <div style={{ padding: '0 16px 14px', borderTop: `1px solid ${C.b}`, paddingTop: 12 }}>
              {[
                { t: '✓  Docker found: 24.0.7',                    c: '#22c55e' },
                { t: '✓  Kernel 5.15 — eBPF supported',            c: '#22c55e' },
                { t: '✓  sensor-acme-prod registered with brain',   c: '#22c55e' },
                { t: '',                                              c: '' },
                { t: 'Dashboard: https://auralisapi.dev/dashboard', c: C.cyan },
              ].map((l, i) => (
                <div key={i} style={{ fontSize: 12, color: l.c || 'transparent', lineHeight: 1.85 }}>{l.t || ' '}</div>
              ))}
            </div>
          </div>

          <div style={{ marginTop: 32 }}>
            <Link href="/install" style={{ textDecoration: 'none' }}>
              <button className="lbtn-lime" style={{ fontSize: 14, padding: '13px 30px' }}>Full Installation Guide →</button>
            </Link>
          </div>
        </div>
      </section>

      {/* ── CTA strip ── */}
      <section ref={rCta} className="reveal" style={{ background: C.lime, padding: '100px 28px' }}>
        <div style={{ maxWidth: 840, margin: '0 auto', textAlign: 'center' }}>
          <span style={{ display: 'block', fontSize: 10, fontWeight: 700, color: C.bg, letterSpacing: '0.18em', opacity: 0.55, marginBottom: 16 }}>// PROTECT YOUR STACK</span>
          <h2 style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: 'clamp(44px, 7vw, 72px)', fontWeight: 800, color: C.bg, marginBottom: 16, letterSpacing: '-0.03em', lineHeight: 1.0 }}>
            PROTECT YOUR<br />APIs NOW.
          </h2>
          <p style={{ fontSize: 14, color: C.bg, opacity: 0.6, marginBottom: 44, lineHeight: 1.65 }}>
            {'// Deploy in 60 seconds. No code changes. No OpenAPI spec required.'}
          </p>
          <div style={{ display: 'flex', gap: 14, justifyContent: 'center', flexWrap: 'wrap' }}>
            {[
              { href: '/install',                label: 'Deploy Sensor →',  bg: C.bg,    col: C.lime, brd: C.bg },
              { href: '/dashboard/attack-arena', label: '◈ Attack Arena',   bg: 'transparent', col: C.bg, brd: C.bg },
              { href: '/dashboard',              label: 'View Dashboard',   bg: 'transparent', col: `${C.bg}99`, brd: `${C.bg}44` },
            ].map(b => (
              <Link key={b.href} href={b.href} style={{ textDecoration: 'none' }}>
                <button style={{
                  background: b.bg, color: b.col, border: `2px solid ${b.brd}`,
                  fontFamily: "'Space Grotesk', sans-serif", fontWeight: 800, fontSize: 13,
                  padding: '13px 28px', cursor: 'pointer', letterSpacing: '0.06em',
                  boxShadow: `4px 4px 0 rgba(0,0,0,0.15)`,
                  transition: 'transform 0.12s, box-shadow 0.12s',
                }}
                  onMouseEnter={e => { const el = e.currentTarget as HTMLButtonElement; el.style.transform = 'translate(-2px,-2px)'; el.style.boxShadow = '6px 6px 0 rgba(0,0,0,0.2)'; }}
                  onMouseLeave={e => { const el = e.currentTarget as HTMLButtonElement; el.style.transform = ''; el.style.boxShadow = '4px 4px 0 rgba(0,0,0,0.15)'; }}
                >{b.label}</button>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer style={{ background: C.bg, borderTop: `1px solid ${C.b}`, padding: '36px 28px' }}>
        <div style={{ maxWidth: 1240, margin: '0 auto', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
          <span style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: 18, fontWeight: 800, color: C.lime }}>AURALIS</span>
          <div style={{ display: 'flex', gap: 28, flexWrap: 'wrap' }}>
            {[
              { href: '/install',                label: 'Install' },
              { href: '/dashboard',              label: 'Dashboard' },
              { href: '/dashboard/attack-arena', label: 'Attack Arena' },
              { href: 'https://github.com/hopepranav08/AuralisAPI', label: 'GitHub', ext: true },
            ].map(l => (
              <a key={l.label} href={l.href}
                target={(l as { ext?: boolean }).ext ? '_blank' : undefined}
                rel={(l as { ext?: boolean }).ext ? 'noopener noreferrer' : undefined}
                style={{ fontSize: 12, color: C.t3, textDecoration: 'none', transition: 'color 0.12s' }}
                onMouseEnter={e => { (e.currentTarget as HTMLAnchorElement).style.color = C.t1; }}
                onMouseLeave={e => { (e.currentTarget as HTMLAnchorElement).style.color = C.t3; }}
              >{l.label}</a>
            ))}
          </div>
          <span style={{ fontSize: 11, color: C.t3 }}>© 2025 AuralisAPI · Autonomous Zero-Trust API Governance</span>
        </div>
      </footer>

    </div>
  );
}
