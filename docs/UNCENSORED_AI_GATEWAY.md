# Unfiltered AI gateway

This hosted inference slice is additive and preserves the existing OpenRouter and local Ollama paths.

## Operator configuration

- `CYBERLAB_UNCENSORED_API_KEY`: server-only provider key.
- `CYBERLAB_UNCENSORED_BASE_URL`: explicit HTTPS OpenAI-compatible API base URL.
- `CYBERLAB_UNCENSORED_MODELS`: JSON array of model IDs, display names and context lengths.
- Tool calling is opt-in per model by setting `"tools": true` on an entry, only after verifying that the exact provider endpoint, model template and vLLM/tool parser support OpenAI-compatible function calling. Example:

```env
CYBERLAB_UNCENSORED_MODELS=[{"id":"provider/model-id","name":"Research model","contextLength":32768,"tools":true}]
```

Do not set `tools:true` just because a model is open-weight or the provider accepts the request parameter. Tool calling remains disabled unless the operator explicitly enables it. The public catalogue exposes only the boolean capability, never provider secrets.

## Read-only tools

The `/api/agent/uncensored/tools` route supports two allowlisted tools:

- `dns_intelligence`: passive DNS-over-HTTPS lookups for A, AAAA, MX, NS and TXT records. It does not connect to the target or run a scan.
- `cve_lookup`: public NIST NVD API v2 lookup by CVE ID or keyword.

The server validates all arguments independently of model-provided JSON, limits each research turn to four calls and four provider rounds, bounds request and response sizes, applies network timeouts, and records source, observed timestamp and returned evidence separately from model-generated analysis. External tool output is treated as untrusted data, not instructions. The route is authenticated, subscription-gated and uses per-user token reservations/settlement. The per-request reservation ceiling is 60,000 tokens; standard inference reserves 10,000 and specialist orchestration reserves 30,000. Settlement records the provider-reported total without silently clamping it to the old 10,000-token ceiling. The monthly default remains 200,000 tokens.

No active scanning, exploitation, credential access, file changes or host execution is exposed by this tool loop. Tool outputs are evidence snapshots, not proof of exploitability or a substitute for validating scope.

## Hosted deployment note

The Qwen2.5-7B-Instruct-abliterated-v2 checkpoint is a proposed hosted GPU target, not a provisioned endpoint. Verify its tool-call template/parser and real provider behaviour before setting `tools:true`. No live model/tool compatibility test has yet been performed.

The monthly token allowance is a starter platform control, not a financial billing meter. Add provider-cost metering, team budgets, concurrency controls, abuse controls and retention policy before public scale.
