# Unfiltered AI gateway

This is the first additive hosted-inference slice. It introduces a provider-independent server route for an explicitly configured uncensored/abliterated model provider while preserving the existing OpenRouter and local Ollama paths.

## User-facing behaviour

- Models are configured by the operator in the server-only `CYBERLAB_UNCENSORED_MODELS` JSON environment variable.
- Each configured entry has an upstream model `id`, optional display `name`, and optional numeric `contextLength`.
- The public model identifier is prefixed with `uncensored:`; the prefix is removed only inside the server gateway.
- The model is called through an OpenAI-compatible `/chat/completions` endpoint.
- `CYBERLAB_UNCENSORED_BASE_URL` must be explicitly configured as an HTTPS OpenAI-compatible API base URL. CyberLab does not guess or silently select a provider endpoint.
- The API key is server-only: `CYBERLAB_UNCENSORED_API_KEY` (or `UNCENSOREDLLM_API_KEY`).
- The route requires a signed-in Supabase user and an active/comped subscription.
- Usage reservations and actual token settlements are stored in `ai_usage_events`; the initial default allowance is 200,000 tokens per user per calendar month, with a 4,096-token reservation per single-agent request and 10,000 tokens for specialist-team requests.

## Recommended hosted deployment target

The initial checkpoint under consideration is `huihui-ai/Qwen2.5-7B-Instruct-abliterated-v2`. Its Hugging Face repository lists an Apache-2.0 licence, vLLM serving instructions and approximately 15.2 GB of model files. This is not suitable for a 4 GB local machine; serve it on hosted GPU infrastructure so every CyberLab user can access the same managed endpoint without installing Ollama or Kali.

RunPod's vLLM Serverless worker exposes an OpenAI-compatible base URL in this form:

```text
https://api.runpod.ai/v2/<ENDPOINT_ID>/openai/v1
```

For this model, the planned server configuration is:

- `CYBERLAB_UNCENSORED_API_KEY`: RunPod API key, stored only as a server-side secret
- `CYBERLAB_UNCENSORED_BASE_URL`: the endpoint URL above
- `CYBERLAB_UNCENSORED_MODELS`: JSON entry whose upstream ID is `huihui-ai/Qwen2.5-7B-Instruct-abliterated-v2`

This is a deployment target, not a claim that a RunPod endpoint has been created or tested. The operator must provision the GPU endpoint, validate vLLM compatibility and confirm cold-start, concurrency and cost behaviour before enabling it. Tool calling is model/parser-dependent and is not enabled in this gateway slice.

References: [Hugging Face model card and files](https://huggingface.co/huihui-ai/Qwen2.5-7B-Instruct-abliterated-v2), [RunPod vLLM worker documentation](https://github.com/runpod-workers/worker-vllm).

## Required environment configuration

```env
CYBERLAB_UNCENSORED_API_KEY=server-side-secret
CYBERLAB_UNCENSORED_BASE_URL=https://your-provider.example/v1
CYBERLAB_UNCENSORED_MODELS=[{"id":"provider/model-id","name":"Unfiltered model","contextLength":32768}]
```

Never put the provider key in `NEXT_PUBLIC_*` variables or browser storage. Do not commit it.

## Migration

Apply `supabase/migrations/202611140001_ai_usage_gateway.sql` after the existing billing migrations. The service-role key is required for usage reservation and settlement; it is never exposed to the browser.

## Current limitations (do not misrepresent)

- Single-agent and role-conditioned specialist analysis are supported. Specialist passes use the same configured model and are not independent evidence sources. This first slice does not yet expose tool calling or image/audio input through this provider.
- The model catalogue is operator-configured. It does not automatically certify that a model is uncensored, safe, high quality, or actually available from the upstream provider.
- The configured provider URL, API key, model IDs and OpenAI-compatible protocol must be verified against the selected provider account before enabling it.
- Abandoned usage reservations older than 20 minutes are expired during the next reservation for that user. A failed request is settled at zero recorded tokens; provider-side billing may still occur for failed/aborted requests, so reconcile provider invoices separately.
- The monthly allowance is a starter platform control, not a financial billing meter. Add provider-cost accounting, team budgets, concurrency limits, abuse controls, and retention policy before public scale.
- The route keeps ordinary platform authentication, subscription and execution authorisation boundaries. The model's response style is not a permission grant to operate on third-party systems.
