import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
    title: "AuralisAPI — Autonomous Zero-Trust API Governance",
    description: "Stop Zombie APIs before they haunt your production.",
    themeColor: "#0c0c0c",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
    return (
        <html lang="en" suppressHydrationWarning>
            <head>
                <meta name="color-scheme" content="dark" />
                <meta name="theme-color" content="#0c0c0c" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
            </head>
            <body>{children}</body>
        </html>
    );
}
