import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
    title: "AuralisAPI — Intelligence Dashboard",
    description: "Autonomous Zero-Trust Perimeter via eBPF-Driven Zombie API Discovery",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
    return (
        <html lang="en">
            <body>{children}</body>
        </html>
    );
}
