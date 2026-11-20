import type { Metadata } from "next";
import "./globals.css";
import CyberBackground from "./cyber-background";

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
      <body><CyberBackground />{children}</body>
    </html>
  );
}