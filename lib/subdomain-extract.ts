// Pure, dependency-free helper: fold crt.sh Certificate Transparency rows into
// unique in-scope subdomains. Kept in its own module so it can be unit-tested
// without the research engine's provider dependencies.
export function extractSubdomains(rows: unknown, domain: string): string[] {
  const base = domain.toLowerCase();
  const found = new Set<string>();
  if (Array.isArray(rows)) {
    for (const row of rows) {
      const value = row && typeof row === "object" ? (row as { name_value?: unknown }).name_value : undefined;
      if (typeof value !== "string") continue;
      for (const raw of value.split(/\s+/)) {
        const name = raw.trim().toLowerCase().replace(/^\*\./, "");
        if (name === base || name.endsWith("." + base)) found.add(name);
      }
    }
  }
  return [...found].sort().slice(0, 200);
}
