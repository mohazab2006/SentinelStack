import "./globals.css";
import type { ReactNode } from "react";
import { DM_Sans, JetBrains_Mono } from "next/font/google";

const sans = DM_Sans({
  subsets: ["latin"],
  variable: "--font-sans",
  display: "swap"
});

const mono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap"
});

export const metadata = {
  title: "SentinelStack — Security overview",
  description: "SentinelStack security operations and telemetry"
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body className="app-body">{children}</body>
    </html>
  );
}
