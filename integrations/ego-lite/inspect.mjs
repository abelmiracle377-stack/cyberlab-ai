// CyberLab read-only ego(lite) smoke test.
// Replace this value only with a target you own or are authorised to inspect.
const targetUrl = "https://example.com";

const parsed = new URL(targetUrl);
if (!["http:", "https:"].includes(parsed.protocol)) {
  throw new Error("Only HTTP and HTTPS targets are supported.");
}

const task = await taskSpace("CyberLab authorised browser inspection");
const page = task.page("p1");

try {
  await page.goto(targetUrl);
  const snapshot = await page.snapshot();
  console.log(JSON.stringify({
    integration: "ego(lite)",
    mode: "read-only",
    target: parsed.origin,
    pageSnapshot: snapshot,
    limitations: [
      "This smoke test does not run vulnerability payloads.",
      "This smoke test does not read or export cookies, passwords, or tokens.",
      "A page snapshot is not proof that a vulnerability exists."
    ]
  }, null, 2));
} finally {
  // Keep the page available for the operator to review in the ego(lite) Space.
  await task.finish({ keep: ["p1"] });
}
