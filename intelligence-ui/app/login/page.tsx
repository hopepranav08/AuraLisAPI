'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

const DEMO_EMAIL    = 'admin@auralisapi.dev';
const DEMO_PASSWORD = 'auralis2025';

export default function LoginPage() {
    const [email, setEmail]       = useState('');
    const [password, setPassword] = useState('');
    const [error, setError]       = useState('');
    const [loading, setLoading]   = useState(false);
    const [showPw, setShowPw]     = useState(false);
    const router = useRouter();

    async function handleSubmit(e: React.FormEvent) {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            const res = await fetch('/brain/auth/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email.trim(), password }),
                signal: AbortSignal.timeout(8000),
            });
            if (res.ok) {
                const { access_token, expires_in } = await res.json();
                localStorage.setItem('auralis_auth', JSON.stringify({
                    email: email.trim(),
                    expiry: Date.now() + (expires_in ?? 86400) * 1000,
                }));
                localStorage.setItem('auralis_brain_token', access_token);
                router.replace('/dashboard');
            } else {
                const body = await res.json().catch(() => ({}));
                setError(body.detail ?? 'Invalid credentials.');
                setLoading(false);
            }
        } catch {
            // Brain unreachable — fall back to local credential check for dev mode
            if (email.trim() === DEMO_EMAIL && password === DEMO_PASSWORD) {
                localStorage.setItem('auralis_auth', JSON.stringify({
                    email: email.trim(),
                    expiry: Date.now() + 24 * 60 * 60 * 1000,
                }));
                localStorage.removeItem('auralis_brain_token');
                router.replace('/dashboard');
            } else {
                setError('Could not reach the brain service. Check that Docker is running.');
                setLoading(false);
            }
        }
    }

    function fillDemo() {
        setEmail(DEMO_EMAIL);
        setPassword(DEMO_PASSWORD);
        setError('');
    }

    return (
        <div className="login-root">
            {/* Subtle dot grid background */}
            <div style={{
                position: 'absolute', inset: 0, pointerEvents: 'none',
                backgroundImage: 'radial-gradient(var(--b1) 1px, transparent 1px)',
                backgroundSize: '28px 28px',
            }} />

            {/* Back link */}
            <Link href="/" style={{
                position: 'absolute', top: '20px', left: '20px',
                display: 'flex', alignItems: 'center', gap: '6px',
                color: 'var(--t3)', fontSize: '11px', textDecoration: 'none',
                fontFamily: 'var(--mono)',
                transition: 'color 0.12s',
            }}
                onMouseEnter={e => { (e.currentTarget as HTMLAnchorElement).style.color = 'var(--t1)'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLAnchorElement).style.color = 'var(--t3)'; }}
            >
                ← back
            </Link>

            <div className="login-card" style={{ position: 'relative', zIndex: 1 }}>
                {/* Logo */}
                <div>
                    <div className="login-logo">AURALIS</div>
                    <div className="login-sub">// intelligence dashboard</div>
                </div>

                {/* Form */}
                <form style={{ display: 'flex', flexDirection: 'column', gap: '16px' }} onSubmit={handleSubmit}>
                    {error && <div className="login-error">{error}</div>}

                    <div className="login-field">
                        <label htmlFor="email">EMAIL</label>
                        <input
                            id="email"
                            type="email"
                            placeholder="admin@auralisapi.dev"
                            value={email}
                            onChange={e => setEmail(e.target.value)}
                            required
                            autoComplete="email"
                        />
                    </div>

                    <div className="login-field">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                            <label htmlFor="password" style={{ marginBottom: 0 }}>PASSWORD</label>
                            <button
                                type="button"
                                onClick={() => setShowPw(v => !v)}
                                style={{ background: 'none', border: 'none', color: 'var(--t3)', fontSize: '11px', cursor: 'pointer', fontFamily: 'var(--mono)', padding: 0 }}
                            >
                                {showPw ? 'hide' : 'show'}
                            </button>
                        </div>
                        <input
                            id="password"
                            type={showPw ? 'text' : 'password'}
                            placeholder="••••••••••••"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            required
                            autoComplete="current-password"
                        />
                    </div>

                    <button
                        type="submit"
                        className="btn btn--solid btn--lg"
                        disabled={loading}
                        style={{ width: '100%', justifyContent: 'center', borderRadius: 0 }}
                    >
                        {loading ? (
                            <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                                <span className="spinner" />
                                SIGNING IN…
                            </span>
                        ) : 'SIGN IN →'}
                    </button>
                </form>

                {/* Demo credentials */}
                <div className="login-demo">
                    <div style={{ fontSize: '10px', fontWeight: 700, color: 'var(--t3)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '10px', fontFamily: 'var(--sans)' }}>
                        // USE DEMO CREDENTIALS
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', fontSize: '12px' }}>
                        <span style={{ color: 'var(--t3)' }}>email</span>
                        <span style={{ color: 'var(--t1)', fontWeight: 600 }}>{DEMO_EMAIL}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px', fontSize: '12px' }}>
                        <span style={{ color: 'var(--t3)' }}>password</span>
                        <span style={{ color: 'var(--t1)', fontWeight: 600 }}>{DEMO_PASSWORD}</span>
                    </div>
                    <button
                        type="button"
                        onClick={fillDemo}
                        className="btn"
                        style={{ width: '100%', justifyContent: 'center', borderRadius: 0 }}
                    >
                        fill demo credentials
                    </button>
                </div>

                <div style={{ fontSize: '11px', color: 'var(--t3)', textAlign: 'center', fontFamily: 'var(--mono)' }}>
                    <Link href="/" style={{ color: 'var(--t3)', textDecoration: 'none' }}
                        onMouseEnter={e => { (e.currentTarget as HTMLAnchorElement).style.color = 'var(--t1)'; }}
                        onMouseLeave={e => { (e.currentTarget as HTMLAnchorElement).style.color = 'var(--t3)'; }}
                    >← return to homepage</Link>
                </div>
            </div>
        </div>
    );
}
