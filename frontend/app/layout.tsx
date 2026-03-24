import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "SentinelStack Dashboard",
  description: "Threat detection, alerts, and automated response dashboard"
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
