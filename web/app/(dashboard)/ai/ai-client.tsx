"use client";

import { useEffect, useRef, useState, useTransition } from "react";
import { sendChat, type ChatMessage } from "./actions";
import { AI_PROVIDERS } from "@/lib/ai-providers";
import { loadAIConfig, saveAIConfig, type AIConfig } from "@/lib/ai-config";

function Markdown({ text }: { text: string }) {
  const lines = text.split("\n");
  return (
    <div className="prose">
      {lines.map((line, i) => {
        const t = line.trim();
        if (t.startsWith("### ")) return <h4 key={i}>{t.slice(4)}</h4>;
        if (t.startsWith("## ")) return <h3 key={i}>{t.slice(3)}</h3>;
        if (t.startsWith("- ")) return <div key={i} className="prose-li">• {t.slice(2)}</div>;
        if (/^\d+\.\s/.test(t)) return <div key={i} className="prose-li">{t}</div>;
        if (t === "") return <div key={i} style={{ height: 8 }} />;
        return <p key={i}>{line}</p>;
      })}
    </div>
  );
}

export default function AIClient() {
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState("");

  // Provider settings (persisted to localStorage)
  const [provider, setProvider] = useState("openai");
  const [apiKey, setApiKey] = useState("");
  const [baseURL, setBaseURL] = useState(AI_PROVIDERS[0].baseURL);
  const [model, setModel] = useState(AI_PROVIDERS[0].models[0]);
  const [showSettings, setShowSettings] = useState(false);

  // Conversation state
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const saved = loadAIConfig();
    setProvider(saved.provider || "openai");
    setApiKey(saved.apiKey || "");
    setBaseURL(saved.baseURL || AI_PROVIDERS[0].baseURL);
    setModel(saved.model || AI_PROVIDERS[0].models[0]);
    if (!saved.apiKey) setShowSettings(true);
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, pending]);

  function persist(key: string, url: string, mdl: string, prov: string) {
    saveAIConfig({ apiKey: key, baseURL: url, model: mdl, provider: prov });
  }

  function selectProvider(id: string) {
    const p = AI_PROVIDERS.find((x) => x.id === id);
    const nextURL = p?.baseURL ?? "";
    const nextModel = p?.models?.[0] ?? "";
    setProvider(id);
    setBaseURL(nextURL);
    setModel(nextModel);
    persist(apiKey, nextURL, nextModel, id);
  }

  const config: AIConfig = { apiKey, baseURL, model, provider };

  function handleSend(e?: React.FormEvent) {
    if (e) e.preventDefault();
    const text = draft.trim();
    if (!text || pending) return;
    setError("");
    const next: ChatMessage[] = [...messages, { role: "user", content: text }];
    setMessages(next);
    setDraft("");
    startTransition(() => {
      sendChat(next, config)
        .then((r) => setMessages((prev) => [...prev, { role: "assistant", content: r.reply }]))
        .catch((err) => setError(String(err?.message ?? err)));
    });
  }

  function clearChat() {
    setMessages([]);
    setError("");
  }

  const currentProvider = AI_PROVIDERS.find((x) => x.id === provider);

  return (
    <>
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <h2 style={{ margin: 0 }}>Model Settings</h2>
            <p className="subtext">
              {currentProvider?.label ?? "Provider"} · {model || "select a model"}
            </p>
          </div>
          <button className="btn" onClick={() => setShowSettings((v) => !v)}>
            {showSettings ? "Hide settings" : apiKey ? "Change settings" : "Configure AI"}
          </button>
        </div>

        {showSettings && (
          <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 12 }}>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              <div style={{ flex: 1, minWidth: 180 }}>
                <label style={{ fontSize: 13, fontWeight: 600, display: "block", marginBottom: 4 }}>
                  Provider
                </label>
                <select value={provider} onChange={(e) => selectProvider(e.target.value)} style={{ width: "100%" }}>
                  {AI_PROVIDERS.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.label}
                    </option>
                  ))}
                </select>
              </div>
              <div style={{ flex: 1, minWidth: 180 }}>
                <label style={{ fontSize: 13, fontWeight: 600, display: "block", marginBottom: 4 }}>
                  API Key
                </label>
                <input
                  type="password"
                  placeholder={provider === "anthropic" ? "sk-ant-..." : provider === "groq" ? "gsk_..." : "sk-..."}
                  value={apiKey}
                  onChange={(e) => {
                    setApiKey(e.target.value);
                    persist(e.target.value, baseURL, model, provider);
                  }}
                  style={{ width: "100%" }}
                />
              </div>
            </div>

            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              <div style={{ flex: 1, minWidth: 180 }}>
                <label style={{ fontSize: 13, fontWeight: 600, display: "block", marginBottom: 4 }}>
                  Base URL
                </label>
                <input
                  value={baseURL}
                  onChange={(e) => {
                    setBaseURL(e.target.value);
                    persist(apiKey, e.target.value, model, provider);
                  }}
                  style={{ width: "100%" }}
                />
              </div>
              <div style={{ flex: 1, minWidth: 180 }}>
                <label style={{ fontSize: 13, fontWeight: 600, display: "block", marginBottom: 4 }}>
                  Model
                </label>
                <input
                  list="ai-model-options"
                  value={model}
                  onChange={(e) => {
                    setModel(e.target.value);
                    persist(apiKey, baseURL, e.target.value, provider);
                  }}
                  style={{ width: "100%" }}
                />
                <datalist id="ai-model-options">
                  {currentProvider?.models.map((m) => (
                    <option key={m} value={m} />
                  ))}
                </datalist>
              </div>
            </div>

            <p className="subtext">
              Your key is stored locally in this browser and sent directly to the provider. Groq, OpenAI,
              OpenRouter, Mistral, Gemini, and Ollama use the OpenAI-compatible API; Anthropic uses its
              native Messages API.
            </p>
          </div>
        )}
      </div>

      {error && (
        <div className="card">
          <div className="login-error">{error}</div>
        </div>
      )}

      <div className="card chat-card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <h2 style={{ margin: 0 }}>Security Assistant</h2>
          {messages.length > 0 && (
            <button className="btn" onClick={clearChat} disabled={pending}>
              New chat
            </button>
          )}
        </div>

        <div className="chat-log">
          {messages.length === 0 && (
            <div className="empty" style={{ textAlign: "center", padding: "32px 8px" }}>
              Ask me about cloud misconfigurations, vulnerabilities, attack paths, or remediation steps.
              <br />
              e.g. &ldquo;My S3 bucket is public and holds production data. What should I do?&rdquo;
            </div>
          )}
          {messages.map((m, i) => (
            <div key={i} className={`chat-row ${m.role === "user" ? "chat-user" : "chat-assistant"}`}>
              <div className="chat-bubble">
                {m.role === "assistant" ? <Markdown text={m.content} /> : <span>{m.content}</span>}
              </div>
            </div>
          ))}
          {pending && (
            <div className="chat-row chat-assistant">
              <div className="chat-bubble chat-typing">Thinking…</div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        <form onSubmit={handleSend} className="chat-input-row">
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="Message the assistant…"
            style={{ flex: 1 }}
          />
          <button type="submit" className="btn chat-send" disabled={pending || !draft.trim()}>
            {pending ? "Sending…" : "Send"}
          </button>
        </form>
      </div>
    </>
  );
}
