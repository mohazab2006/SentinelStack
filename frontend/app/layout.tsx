import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "SentinelStack Dashboard",
  description: "Milestone 1 request visibility dashboard"
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
