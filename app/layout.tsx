import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CyberLab AI — Security Research Workspace",
  description:
    "An open-source AI-assisted cybersecurity research and defensive assessment workspace.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}