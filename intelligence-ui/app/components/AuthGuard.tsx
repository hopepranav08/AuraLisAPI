'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

export function AuthGuard({ children }: { children: React.ReactNode }) {
    const [authed, setAuthed] = useState<boolean | null>(null);
    const router = useRouter();

    useEffect(() => {
        try {
            const raw = localStorage.getItem('auralis_auth');
            if (!raw) { router.replace('/login'); return; }
            const parsed = JSON.parse(raw);
            if (parsed.expiry && parsed.expiry > Date.now()) {
                setAuthed(true);
            } else {
                localStorage.removeItem('auralis_auth');
                router.replace('/login');
            }
        } catch {
            localStorage.removeItem('auralis_auth');
            router.replace('/login');
        }
    }, [router]);

    if (authed === null) {
        return (
            <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100vh',
                background: '#080808',
                flexDirection: 'column',
                gap: '16px',
            }}>
                <span className="spinner" />
                <span style={{ color: '#888888', fontSize: '12px', fontFamily: "'JetBrains Mono', monospace" }}>
                    // checking credentials
                </span>
            </div>
        );
    }

    return <>{children}</>;
}
