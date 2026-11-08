"use client";

export default function SignOutButton() {
  async function signOut() {
    const response = await fetch("/api/auth/signout", { method: "POST" });
    if (!response.ok) throw new Error("Sign out failed. Please try again.");
    window.location.href = "/login";
  }
  return <button onClick={() => void signOut()} style={{ padding: "11px 15px", borderRadius: 7, border: "1px solid #526d59", background: "#1d3926", color: "#e8eee9", cursor: "pointer" }}>Sign out</button>;
}
