'use client';
import React, { useState } from 'react';
import Link from 'next/link';

function CopyBtn({ text }: { text: string }) {
    const [copied, setCopied] = useState(false);
    function copy() {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    }
    return (
        <button
            onClick={copy}
            style={{
                background: 'none',
                border: '1px solid #444',
                color: copied ? '#6bde00' : '#888',
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '11px',
                padding: '3px 8px',
                cursor: 'pointer',
                transition: 'color 0.15s, border-color 0.15s',
                flexShrink: 0,
            }}
        >
            {copied ? '✓ copied' : '⎘ copy'}
        </button>
    );
}

function CodeBlock({ label, code }: { label: string; code: string }) {
    return (
        <div style={{
            border: '2px solid var(--t1, #0f0f0f)',
            boxShadow: '4px 4px 0 var(--t1, #0f0f0f)',
            background: '#0f0f0f',
            marginTop: '0.75rem',
        }}>
            <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '6px 12px',
                borderBottom: '1px solid #222',
                background: '#141414',
            }}>
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: '#555' }}>
                    {label}
                </span>
                <CopyBtn text={code} />
            </div>
            <pre style={{
                margin: 0,
                padding: '14px 16px',
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '13px',
                color: '#e8e6e0',
                lineHeight: 1.65,
                overflowX: 'auto',
                whiteSpace: 'pre',
            }}>{code}</pre>
        </div>
    );
}

const ENV_VARS = [
    { name: 'BRAIN_URL', default: 'https://auralisapi.dev', desc: 'URL of the hosted remediation brain. Use your self-hosted URL for on-prem.' },
    { name: 'COMPANY_TOKEN', default: '(generated at signup)', desc: 'Bearer token issued during onboarding. Used to authenticate sensor events.' },
    { name: 'SENSOR_MODE', default: 'live', desc: '"live" uses real eBPF kernel injection. "mock" replays fixture events (works on any OS).' },
    { name: 'SENSOR_ID', default: 'sensor-<hostname>', desc: 'Unique identifier for this sensor instance. Auto-generated from hostname if not set.' },
    { name: 'REDIS_ADDR', default: '127.0.0.1:6379', desc: 'Local Redis address for the event stream. Required only for self-hosted deployments.' },
    { name: 'METRICS_PORT', default: '9090', desc: 'Port for the drift stats HTTP server (Page-Hinkley metrics).' },
    { name: 'LOG_LEVEL', default: 'info', desc: '"debug" | "info" | "warn" | "error".' },
];

export default function InstallPage() {
    const [tab, setTab] = useState<'cloud' | 'self'>('cloud');

    return (
        <div style={{ minHeight: '100vh', background: 'var(--bg, #f5f4f0)', color: 'var(--t1, #0f0f0f)' }}>

            {/* Nav */}
            <nav style={{
                position: 'fixed', top: 0, left: 0, right: 0, zIndex: 50,
                height: 56, display: 'flex', alignItems: 'center',
                background: 'rgba(12,12,12,0.96)',
                borderBottom: '1px solid var(--b2, #2a2a2a)',
                backdropFilter: 'blur(16px)',
                padding: '0 2rem',
                justifyContent: 'space-between',
            }}>
                <Link href="/" style={{
                    fontFamily: "'Space Grotesk', sans-serif",
                    fontWeight: 800,
                    fontSize: '1.125rem',
                    color: '#b8ff00',
                    textDecoration: 'none',
                    letterSpacing: '-0.01em',
                }}>
                    AURALIS
                </Link>

                <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
                    <Link href="/dashboard" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: 'var(--t2, #888)', textDecoration: 'none', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Dashboard</Link>
                    <Link href="/install" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: '#b8ff00', textDecoration: 'none', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Install</Link>
                    <Link href="/dashboard/attack-arena" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: 'var(--t2, #888)', textDecoration: 'none', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Attack Arena</Link>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <Link href="/login" style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: '0.75rem',
                        color: 'var(--t2, #888)',
                        textDecoration: 'none',
                        padding: '5px 12px',
                        border: '1px solid var(--b2, #2a2a2a)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                    }}>
                        Login
                    </Link>
                    <Link href="/dashboard" style={{
                        fontFamily: "'Space Grotesk', sans-serif",
                        fontSize: '0.75rem',
                        color: '#0c0c0c',
                        background: '#b8ff00',
                        textDecoration: 'none',
                        padding: '6px 14px',
                        fontWeight: 800,
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                    }}>
                        Dashboard →
                    </Link>
                </div>
            </nav>

            {/* Hero */}
            <div style={{
                marginTop: 56,
                padding: '5rem 2rem 3rem',
                borderBottom: '2px solid var(--t1, #f0f0f0)',
                background: 'var(--bg, #0c0c0c)',
                backgroundImage: 'radial-gradient(circle, rgba(255,255,255,0.05) 1px, transparent 1px)',
                backgroundSize: '24px 24px',
            }}>
                <div style={{ maxWidth: 800, margin: '0 auto' }}>
                    <div style={{
                        display: 'inline-flex', alignItems: 'center', gap: '0.5rem',
                        padding: '4px 12px',
                        border: '2px solid #b8ff00',
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: '0.75rem',
                        fontWeight: 700,
                        marginBottom: '1.5rem',
                        background: '#b8ff00',
                        color: '#0c0c0c',
                    }}>
                        // sensor v1.0 · 12MB Go binary
                    </div>
                    <h1 style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontWeight: 900,
                        fontSize: 'clamp(2rem, 5vw, 3.5rem)',
                        lineHeight: 1.05,
                        letterSpacing: '-0.03em',
                        margin: '0 0 1.25rem',
                        color: 'var(--t1, #f0f0f0)',
                    }}>
                        Deploy in <span style={{ background: '#b8ff00', color: '#0c0c0c', padding: '0 6px' }}>60 seconds</span>
                    </h1>
                    <p style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: '1rem',
                        color: 'var(--t2, #888888)',
                        lineHeight: 1.7,
                        maxWidth: 560,
                        margin: 0,
                    }}>
                        One command deploys the eBPF sensor on any Linux server. No code changes. No OpenAPI spec required.
                    </p>
                </div>
            </div>

            {/* Main content */}
            <div style={{ maxWidth: 800, margin: '0 auto', padding: '3rem 2rem 6rem' }}>

                {/* Requirements */}
                <div style={{ marginBottom: '3rem' }}>
                    <h2 style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontWeight: 800,
                        fontSize: '0.875rem',
                        textTransform: 'uppercase',
                        letterSpacing: '0.1em',
                        color: 'var(--t3, #555)',
                        marginBottom: '1rem',
                    }}>
                        // requirements
                    </h2>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
                        {[
                            { icon: 'LX', title: 'Linux Host', desc: 'Ubuntu 20.04+, Debian 11+, Amazon Linux 2023, RHEL 8+' },
                            { icon: '≥5', title: 'Kernel ≥ 5.8', desc: 'Required for eBPF live mode. Use mock mode on older kernels or Windows.' },
                            { icon: 'DK', title: 'Docker', desc: 'Docker 20.10+ with access to run privileged containers.' },
                        ].map(r => (
                            <div key={r.title} style={{
                                border: '1px solid var(--b2, #2a2a2a)',
                                background: 'var(--s1, #111)',
                                padding: '1.25rem',
                                borderTop: '3px solid #b8ff00',
                            }}>
                                <div style={{
                                    display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                                    width: 36, height: 36,
                                    background: '#b8ff00',
                                    color: '#0c0c0c',
                                    fontFamily: "'JetBrains Mono', monospace",
                                    fontWeight: 900,
                                    fontSize: '0.75rem',
                                    marginBottom: '0.75rem',
                                }}>
                                    {r.icon}
                                </div>
                                <h4 style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, fontSize: '0.875rem', margin: '0 0 0.5rem', color: 'var(--t1, #f0f0f0)' }}>{r.title}</h4>
                                <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: 'var(--t2, #888)', margin: 0, lineHeight: 1.6 }}>{r.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Tabs */}
                <div style={{ marginBottom: '2rem', borderBottom: '2px solid var(--b2, #2a2a2a)', display: 'flex', gap: 0 }}>
                    {(['cloud', 'self'] as const).map(t => (
                        <button
                            key={t}
                            onClick={() => setTab(t)}
                            style={{
                                padding: '0.75rem 1.5rem',
                                background: tab === t ? '#b8ff00' : 'transparent',
                                border: 'none',
                                borderRight: '1px solid var(--b2, #2a2a2a)',
                                color: tab === t ? '#0c0c0c' : 'var(--t3, #555)',
                                fontWeight: tab === t ? 700 : 400,
                                fontSize: '0.8125rem',
                                cursor: 'pointer',
                                fontFamily: "'JetBrains Mono', monospace",
                                transition: 'all 0.1s',
                                letterSpacing: '0.02em',
                            }}
                        >
                            {t === 'cloud' ? '// cloud (hosted)' : '// self-hosted'}
                        </button>
                    ))}
                </div>

                {tab === 'cloud' ? (
                    <>
                        <Step num={1} title="Get your company token">
                            <p style={pStyle}>Sign up at <strong>auralisapi.dev</strong> and copy your company token from the dashboard. This authenticates your sensor with the hosted brain.</p>
                            <CodeBlock label="your token" code="COMPANY_TOKEN=acme-abc123xyz" />
                        </Step>

                        <Step num={2} title="Run the one-command installer">
                            <p style={pStyle}>SSH into your Linux server and run this command. It checks prerequisites, pulls the sensor image, and registers with the brain automatically.</p>
                            <CodeBlock
                                label="bash — your server"
                                code={`curl -sSL https://auralisapi.dev/install.sh | \\
  BRAIN_URL=https://auralisapi.dev \\
  COMPANY_TOKEN=acme-abc123xyz bash`}
                            />
                        </Step>

                        <Step num={3} title="Open your dashboard">
                            <p style={pStyle}>Within 30 seconds, your endpoints appear in the Intelligence Dashboard. Zombie APIs are flagged automatically. Incidents trigger AI-powered remediation.</p>
                            <Link href="/dashboard" style={{
                                display: 'inline-block', marginTop: '1rem',
                                padding: '10px 20px',
                                background: '#6bde00',
                                border: '2px solid var(--t1, #0f0f0f)',
                                boxShadow: '3px 3px 0 var(--t1, #0f0f0f)',
                                fontFamily: "'JetBrains Mono', monospace",
                                fontWeight: 700,
                                fontSize: '0.875rem',
                                color: '#0f0f0f',
                                textDecoration: 'none',
                            }}>
                                open intelligence dashboard →
                            </Link>
                        </Step>
                    </>
                ) : (
                    <>
                        <Step num={1} title="Clone the repository">
                            <CodeBlock
                                label="bash"
                                code={`git clone https://github.com/hopepranav08/AuralisAPI.git\ncd AuralisAPI`}
                            />
                        </Step>

                        <Step num={2} title="Configure environment">
                            <p style={pStyle}>Copy the example env file and fill in your API keys. Only <code style={{ fontFamily: "'JetBrains Mono', monospace", background: 'var(--s3, #1e1e1e)', color: '#b8ff00', padding: '1px 5px' }}>ANTHROPIC_API_KEY</code> is required for AI features.</p>
                            <CodeBlock
                                label="bash"
                                code={`cp .env.example .env
# Edit .env — minimum required:
ANTHROPIC_API_KEY=sk-ant-your-key-here
GITHUB_TOKEN=ghp_your-token   # for PR creation
GITHUB_REPO=yourorg/yourrepo`}
                            />
                        </Step>

                        <Step num={3} title="Start all services">
                            <p style={pStyle}><strong>Mock mode</strong> (any OS, no kernel requirements) — replays fixture events to demonstrate the full pipeline.</p>
                            <CodeBlock label="bash — mock mode (recommended for dev)" code="make up" />
                            <div style={{ height: '1rem' }} />
                            <p style={pStyle}><strong>Live mode</strong> (Linux kernel ≥ 5.8 required) — real eBPF kernel injection.</p>
                            <CodeBlock label="bash — live mode (Linux only)" code="make up-live" />
                        </Step>

                        <Step num={4} title="Access services">
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginTop: '0.75rem' }}>
                                {[
                                    { name: 'Intelligence Dashboard', url: 'http://localhost:3000' },
                                    { name: 'Remediation Brain API', url: 'http://localhost:8000/docs' },
                                    { name: 'API Gateway', url: 'http://localhost:8080' },
                                    { name: 'Drift / Sensor Metrics', url: 'http://localhost:9090/drift/stats' },
                                ].map(s => (
                                    <div key={s.name} style={{
                                        border: '1px solid var(--b2, #2a2a2a)',
                                        background: 'var(--s1, #111)',
                                        padding: '1rem',
                                        borderLeft: '3px solid #b8ff00',
                                    }}>
                                        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, fontSize: '0.7rem', marginBottom: '0.375rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--t3, #555)' }}>{s.name}</div>
                                        <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: '#b8ff00' }}>{s.url}</code>
                                    </div>
                                ))}
                            </div>
                        </Step>
                    </>
                )}

                {/* Kubernetes */}
                <div style={{
                    marginTop: '3rem',
                    border: '1px solid var(--b2, #2a2a2a)',
                    borderTop: '3px solid #b8ff00',
                    background: 'var(--s1, #111)',
                }}>
                    <div style={{
                        padding: '0.875rem 1.5rem',
                        borderBottom: '1px solid var(--b2, #2a2a2a)',
                        fontFamily: "'JetBrains Mono', monospace",
                        fontWeight: 700,
                        fontSize: '0.875rem',
                        display: 'flex', alignItems: 'center', gap: '0.75rem',
                        color: 'var(--t1, #f0f0f0)',
                    }}>
                        <span style={{ background: '#b8ff00', color: '#0c0c0c', padding: '2px 8px', fontSize: '0.75rem', fontWeight: 900 }}>K8S</span>
                        Kubernetes DaemonSet
                    </div>
                    <div style={{ padding: '1.5rem' }}>
                        <p style={{ ...pStyle, marginTop: 0 }}>For Kubernetes clusters, deploy as a DaemonSet so every node gets the sensor automatically.</p>
                        <CodeBlock
                            label="kubectl"
                            code={`kubectl create secret generic auralis-token \\
  --from-literal=COMPANY_TOKEN=acme-abc123xyz \\
  --from-literal=BRAIN_URL=https://auralisapi.dev

kubectl apply -f https://auralisapi.dev/k8s/daemonset.yaml`}
                        />
                    </div>
                </div>

                {/* Environment vars */}
                <div style={{ marginTop: '3rem' }}>
                    <h2 style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontWeight: 800,
                        fontSize: '0.875rem',
                        textTransform: 'uppercase',
                        letterSpacing: '0.1em',
                        color: 'var(--t3, #555)',
                        marginBottom: '1rem',
                    }}>
                        // environment variables
                    </h2>
                    <table style={{
                        width: '100%',
                        borderCollapse: 'collapse',
                        border: '1px solid var(--b2, #2a2a2a)',
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: '0.8125rem',
                    }}>
                        <thead>
                            <tr style={{ background: 'var(--s2, #161616)', borderBottom: '2px solid #b8ff00' }}>
                                <th style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 700, whiteSpace: 'nowrap', color: 'var(--t3, #555)', letterSpacing: '0.1em', fontSize: '0.7rem' }}>VARIABLE</th>
                                <th style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 700, whiteSpace: 'nowrap', color: 'var(--t3, #555)', letterSpacing: '0.1em', fontSize: '0.7rem' }}>DEFAULT</th>
                                <th style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 700, color: 'var(--t3, #555)', letterSpacing: '0.1em', fontSize: '0.7rem' }}>DESCRIPTION</th>
                            </tr>
                        </thead>
                        <tbody>
                            {ENV_VARS.map((v, i) => (
                                <tr key={v.name} style={{ background: i % 2 === 0 ? 'var(--s1, #111)' : 'var(--bg, #0c0c0c)', borderTop: '1px solid var(--b1, #1e1e1e)' }}>
                                    <td style={{ padding: '10px 14px', fontWeight: 700, color: '#b8ff00', whiteSpace: 'nowrap' }}>{v.name}</td>
                                    <td style={{ padding: '10px 14px', color: 'var(--t3, #555)', background: 'var(--s2, #161616)', whiteSpace: 'nowrap' }}>{v.default}</td>
                                    <td style={{ padding: '10px 14px', color: 'var(--t2, #888)', lineHeight: 1.5 }}>{v.desc}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                {/* Troubleshooting */}
                <div style={{
                    marginTop: '3rem',
                    border: '1px solid var(--orange, #ff9500)',
                    borderTop: '3px solid var(--orange, #ff9500)',
                    background: 'rgba(255,149,0,0.05)',
                }}>
                    <div style={{
                        padding: '0.875rem 1.5rem',
                        borderBottom: '1px solid rgba(255,149,0,0.3)',
                        fontFamily: "'JetBrains Mono', monospace",
                        fontWeight: 700,
                        fontSize: '0.875rem',
                        color: 'var(--orange, #ff9500)',
                        display: 'flex', alignItems: 'center', gap: '0.5rem',
                    }}>
                        <span style={{ background: 'var(--orange, #ff9500)', color: '#0c0c0c', padding: '2px 8px', fontSize: '0.75rem', fontWeight: 900 }}>WARN</span>
                        Common issues
                    </div>
                    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                        {[
                            { q: 'eBPF verifier error on startup', a: 'Ensure kernel ≥ 5.8. Use SENSOR_MODE=mock for kernels below 5.8 or on Windows/macOS.' },
                            { q: 'Sensor registered but no endpoints appearing', a: 'Wait 30s for the first replay cycle. Check Redis is reachable at 127.0.0.1:6379.' },
                            { q: 'Brain shows "LLM unavailable"', a: 'Set ANTHROPIC_API_KEY in .env. Groq is the fallback — set GROQ_API_KEY if Anthropic is unavailable.' },
                        ].map(item => (
                            <div key={item.q}>
                                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, fontSize: '0.8125rem', color: 'var(--orange, #ff9500)', marginBottom: '0.25rem' }}>{item.q}</div>
                                <div style={{ fontFamily: "'JetBrains Mono', monospace", color: 'var(--t2, #888)', fontSize: '0.75rem', lineHeight: 1.6 }}>{item.a}</div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Footer */}
            <footer style={{
                borderTop: '1px solid var(--b1, #1e1e1e)',
                padding: '2rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '1rem',
                background: 'var(--bg, #0c0c0c)',
            }}>
                <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 800, fontSize: '1.125rem', color: '#b8ff00', letterSpacing: '-0.01em' }}>
                    AURALIS
                </div>
                <div style={{ display: 'flex', gap: '2rem' }}>
                    {[
                        { label: 'home', href: '/' },
                        { label: 'dashboard', href: '/dashboard' },
                        { label: 'github', href: 'https://github.com/hopepranav08/AuralisAPI' },
                    ].map(l => (
                        <Link key={l.label} href={l.href} style={{
                            fontFamily: "'JetBrains Mono', monospace",
                            fontSize: '0.8125rem',
                            color: 'var(--t3, #555)',
                            textDecoration: 'none',
                        }}>
                            {l.label}
                        </Link>
                    ))}
                </div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: 'var(--t3, #555)' }}>
                    © 2025 AuralisAPI · Autonomous Zero-Trust API Governance
                </div>
            </footer>
        </div>
    );
}

const pStyle: React.CSSProperties = {
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '0.875rem',
    color: 'var(--t2, #888888)',
    lineHeight: 1.7,
    margin: '0.75rem 0 0',
};

function Step({ num, title, children }: { num: number; title: string; children: React.ReactNode }) {
    return (
        <div style={{
            display: 'flex',
            gap: '1.5rem',
            marginBottom: '2.5rem',
            paddingBottom: '2.5rem',
            borderBottom: '1px solid var(--b1, #1e1e1e)',
        }}>
            <div style={{
                flexShrink: 0,
                width: 40, height: 40,
                background: '#b8ff00',
                color: '#0c0c0c',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontFamily: "'JetBrains Mono', monospace",
                fontWeight: 900,
                fontSize: '1rem',
            }}>
                {num}
            </div>
            <div style={{ flex: 1 }}>
                <h3 style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontWeight: 700,
                    fontSize: '1rem',
                    margin: '0 0 0.25rem',
                    paddingTop: '0.5rem',
                    color: 'var(--t1, #f0f0f0)',
                }}>
                    {title}
                </h3>
                {children}
            </div>
        </div>
    );
}
