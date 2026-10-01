// Shared BYOK AI configuration stored in the browser.
// The AI chat and the findings "AI Analyze" action both read from here so a
// single key/config drives every AI feature.

export type AIConfig = {
  apiKey?: string;
  baseURL?: string;
  model?: string;
  provider?: string;
};

const KEYS = {
  apiKey: "castra_ai_key",
  baseURL: "castra_ai_base_url",
  model: "castra_ai_model",
  provider: "castra_ai_provider",
};

export function loadAIConfig(): AIConfig {
  if (typeof window === "undefined") return {};
  return {
    apiKey: localStorage.getItem(KEYS.apiKey) ?? "",
    baseURL: localStorage.getItem(KEYS.baseURL) ?? "",
    model: localStorage.getItem(KEYS.model) ?? "",
    provider: localStorage.getItem(KEYS.provider) ?? "",
  };
}

export function saveAIConfig(config: AIConfig) {
  if (typeof window === "undefined") return;
  if (config.apiKey !== undefined) localStorage.setItem(KEYS.apiKey, config.apiKey);
  if (config.baseURL !== undefined) localStorage.setItem(KEYS.baseURL, config.baseURL);
  if (config.model !== undefined) localStorage.setItem(KEYS.model, config.model);
  if (config.provider !== undefined) localStorage.setItem(KEYS.provider, config.provider);
}
