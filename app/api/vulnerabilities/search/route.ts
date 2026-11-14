export const runtime = "nodejs";

const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i;

export async function GET(request: Request) {
  const query = new URL(request.url).searchParams.get("q")?.trim() || "";
  if (query.length < 3 || query.length > 120 || /[<>\u0000-\u001f]/.test(query)) {
    return Response.json({ error: "Enter a CVE ID or keyword between 3 and 120 characters." }, { status: 400 });
  }
  const params = new URLSearchParams({ resultsPerPage: "10" });
  if (CVE_PATTERN.test(query)) params.set("cveId", query.toUpperCase());
  else params.set("keywordSearch", query);

  try {
    const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10000),
      next: { revalidate: 300 },
    });
    if (!response.ok) {
      return Response.json({ error: `NVD returned HTTP ${response.status}. Try again shortly.` }, { status: 502 });
    }
    const data = await response.json();
    const vulnerabilities = (data.vulnerabilities || []).map((entry: any) => {
      const cve = entry.cve || {};
      const description = (cve.descriptions || []).find((item: any) => item.lang === "en")?.value || "No English description supplied.";
      const metrics = cve.metrics || {};
      const metric = metrics.cvssMetricV40?.[0] || metrics.cvssMetricV31?.[0] || metrics.cvssMetricV30?.[0] || metrics.cvssMetricV2?.[0];
      const cvss = metric?.cvssData;
      return {
        id: cve.id || "Unknown",
        description,
        published: cve.published || null,
        modified: cve.lastModified || null,
        status: cve.vulnStatus || "Unknown",
        severity: cvss?.baseSeverity || metric?.baseSeverity || "Not scored",
        score: typeof cvss?.baseScore === "number" ? cvss.baseScore : null,
        vector: cvss?.vectorString || null,
        references: (cve.references || []).slice(0, 5).map((ref: any) => ({ url: ref.url, tags: ref.tags || [] })),
        weaknesses: (cve.weaknesses || []).flatMap((item: any) => item.description || []).filter((item: any) => item.lang === "en").map((item: any) => item.value).slice(0, 5),
      };
    });
    return Response.json({
      query,
      total: data.totalResults || 0,
      results: vulnerabilities,
      source: "NIST National Vulnerability Database (NVD) API 2.0",
      note: "A CVE match is research context, not proof that a particular asset is vulnerable. Verify affected product versions, configuration, exposure and vendor advisories.",
    }, { headers: { "Cache-Control": "public, s-maxage=300, stale-while-revalidate=600" } });
  } catch {
    return Response.json({ error: "Could not reach the NIST NVD service. Please retry." }, { status: 502 });
  }
}
