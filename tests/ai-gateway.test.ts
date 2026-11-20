import { test } from "node:test";
import assert from "node:assert/strict";
import { getUnfilteredModels, getProviderConfig } from "../lib/ai-gateway";

function withEnv(vars: Record<string, string | undefined>, fn: () => void) {
  const prev: Record<string, string | undefined> = {};
  for (const k of Object.keys(vars)) { prev[k] = process.env[k]; if (vars[k] === undefined) delete process.env[k]; else process.env[k] = vars[k]; }
  try { fn(); } finally { for (const k of Object.keys(prev)) { if (prev[k] === undefined) delete process.env[k]; else process.env[k] = prev[k]; } }
}

test("model catalogue parses valid entries and namespaces ids", () => {
  withEnv({ CYBERLAB_UNCENSORED_MODELS: JSON.stringify([
    { id: "llama3.1:70b", name: "Llama 3.1 70B", contextLength: 131072, tools: true },
    { id: "dolphin-mixtral" },
  ]) }, () => {
    const models = getUnfilteredModels();
    assert.equal(models.length, 2);
    assert.equal(models[0].id, "uncensored:llama3.1:70b");
    assert.equal(models[0].supportsTools, true);
    assert.equal(models[0].uncensored, true);
    assert.equal(models[1].id, "uncensored:dolphin-mixtral");
    assert.equal(models[1].supportsTools, false);
  });
});

test("model catalogue rejects bad ids and bad context lengths", () => {
  withEnv({ CYBERLAB_UNCENSORED_MODELS: JSON.stringify([
    { id: "bad id!" },                    // illegal chars
    { id: "ok-model", contextLength: 10 }, // too small
    { id: "fine-model", contextLength: 8192 },
  ]) }, () => {
    const models = getUnfilteredModels();
    assert.equal(models.length, 1);
    assert.equal(models[0].id, "uncensored:fine-model");
  });
  withEnv({ CYBERLAB_UNCENSORED_MODELS: undefined }, () => assert.deepEqual(getUnfilteredModels(), []));
  withEnv({ CYBERLAB_UNCENSORED_MODELS: "not json" }, () => assert.deepEqual(getUnfilteredModels(), []));
});

test("provider config requires https and strips trailing slash", () => {
  withEnv({ CYBERLAB_UNCENSORED_BASE_URL: "https://ollama.example/v1/" }, () => {
    assert.equal(getProviderConfig().baseUrl, "https://ollama.example/v1");
  });
  withEnv({ CYBERLAB_UNCENSORED_BASE_URL: "http://ollama.example/v1" }, () => {
    assert.equal(getProviderConfig().baseUrl, ""); // http rejected
  });
});

test("keyless opt-in and completions path override (Ollama)", () => {
  withEnv({ CYBERLAB_UNCENSORED_ALLOW_KEYLESS: "true", CYBERLAB_UNCENSORED_COMPLETIONS_PATH: "/v1/chat/completions" }, () => {
    const cfg = getProviderConfig();
    assert.equal(cfg.allowKeyless, true);
    assert.equal(cfg.completionsPath, "/v1/chat/completions");
  });
  withEnv({ CYBERLAB_UNCENSORED_ALLOW_KEYLESS: undefined, CYBERLAB_UNCENSORED_COMPLETIONS_PATH: "bad path ;rm" }, () => {
    const cfg = getProviderConfig();
    assert.equal(cfg.allowKeyless, false);
    assert.equal(cfg.completionsPath, "/chat/completions"); // invalid path falls back to default
  });
});
