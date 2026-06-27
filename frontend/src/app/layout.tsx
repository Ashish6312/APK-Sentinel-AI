import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "APK Sentinel AI — Enterprise SOC Platform",
  description: "AI-powered Android malware analysis platform. Real-time static analysis, dynamic sandboxing, MITRE ATT&CK mapping, and executive threat reports. Built for enterprise SOC teams.",
  keywords: ["APK analysis", "Android malware", "SOC platform", "threat intelligence", "MITRE ATT&CK"],
  openGraph: {
    title: "APK Sentinel AI",
    description: "Enterprise-grade Android malware detection & analysis",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&family=Rajdhani:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="cyber-grid">
        {children}
      </body>
    </html>
  );
}
