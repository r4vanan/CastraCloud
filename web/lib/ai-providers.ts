export type AIProvider = {
  id: string;
  label: string;
  baseURL: string;
  models: string[];
};

export const AI_PROVIDERS: AIProvider[] = [
  {
    id: "openai",
    label: "OpenAI",
    baseURL: "https://api.openai.com/v1",
    models: ["gpt-4o", "gpt-4o-mini", "gpt-4.1", "o3-mini"],
  },
  {
    id: "groq",
    label: "Groq",
    baseURL: "https://api.groq.com/openai/v1",
    models: ["openai/gpt-oss-20b", "openai/gpt-oss-120b"],
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    baseURL: "https://api.deepseek.com",
    models: ["deepseek-chat", "deepseek-reasoner"],
  },
  {
    id: "anthropic",
    label: "Anthropic (Claude)",
    baseURL: "https://api.anthropic.com",
    models: ["claude-3-5-sonnet-latest", "claude-3-5-haiku-latest", "claude-3-opus-latest"],
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    baseURL: "https://openrouter.ai/api/v1",
    models: ["openai/gpt-4o", "anthropic/claude-3.5-sonnet", "meta-llama/llama-3.3-70b-instruct"],
  },
  {
    id: "mistral",
    label: "Mistral",
    baseURL: "https://api.mistral.ai/v1",
    models: ["mistral-large-latest", "mistral-small-latest"],
  },
  {
    id: "gemini",
    label: "Google Gemini",
    baseURL: "https://generativelanguage.googleapis.com/v1beta/openai",
    models: ["gemini-2.0-flash", "gemini-1.5-pro"],
  },
  {
    id: "ollama",
    label: "Ollama (local)",
    baseURL: "http://localhost:11434/v1",
    models: ["llama3.1", "llama3.3", "mistral"],
  },
];
