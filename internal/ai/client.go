// Package ai provides a bring-your-own-key (BYOK) LLM client for threat
// analysis, summarization, and conversational security assistance. It targets
// any OpenAI-compatible chat completions API (OpenAI, Groq, OpenRouter,
// Ollama, Mistral, Google Gemini, vLLM, etc.) as well as Anthropic's native
// Messages API, so users can supply their own provider and model.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Provider identifies a first-class LLM provider. The empty string denotes a
// generic OpenAI-compatible endpoint.
const (
	ProviderOpenAI     = "openai"
	ProviderAnthropic  = "anthropic"
	ProviderGroq       = "groq"
	ProviderDeepSeek   = "deepseek"
	ProviderOpenRouter = "openrouter"
	ProviderOllama     = "ollama"
	ProviderMistral    = "mistral"
	ProviderGemini     = "gemini"
)

// Config configures the LLM provider.
type Config struct {
	BaseURL    string // endpoint root, e.g. https://api.openai.com/v1 or https://api.anthropic.com
	APIKey     string
	Model      string
	Provider   string // "" (OpenAI-compatible), "anthropic", or a provider constant
	HTTPClient *http.Client
}

// Client is a minimal LLM client for OpenAI-compatible and Anthropic APIs.
type Client struct {
	cfg  Config
	http *http.Client
}

// Message is a single chat turn.
type Message struct {
	Role    string `json:"role"` // system | user | assistant
	Content string `json:"content"`
}

// New validates the config and returns a client.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("ai: api key is required (set AI_API_KEY or enter it in the assistant)")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL(cfg.Provider)
	}
	if cfg.Model == "" {
		cfg.Model = defaultModel(cfg.Provider)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	return &Client{
		cfg:  cfg,
		http: client,
	}, nil
}

func defaultBaseURL(provider string) string {
	switch strings.ToLower(provider) {
	case ProviderAnthropic:
		return "https://api.anthropic.com"
	case ProviderGroq:
		return "https://api.groq.com/openai/v1"
	case ProviderDeepSeek:
		return "https://api.deepseek.com"
	case ProviderOpenRouter:
		return "https://openrouter.ai/api/v1"
	case ProviderOllama:
		return "http://localhost:11434/v1"
	case ProviderMistral:
		return "https://api.mistral.ai/v1"
	case ProviderGemini:
		return "https://generativelanguage.googleapis.com/v1beta/openai"
	default:
		return "https://api.openai.com/v1"
	}
}

func defaultModel(provider string) string {
	switch strings.ToLower(provider) {
	case ProviderAnthropic:
		return "claude-3-5-sonnet-latest"
	case ProviderGroq:
		return "openai/gpt-oss-20b"
	case ProviderDeepSeek:
		return "deepseek-chat"
	case ProviderOllama:
		return "llama3.1"
	default:
		return "gpt-4o-mini"
	}
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatResponse struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

// Chat sends a single-turn system+user prompt and returns the assistant reply.
func (c *Client) Chat(ctx context.Context, system, user string) (string, error) {
	return c.ChatMessages(ctx, system, []Message{{Role: "user", Content: user}})
}

// ChatMessages sends a conversation (system prompt plus prior turns) and
// returns the assistant reply.
func (c *Client) ChatMessages(ctx context.Context, system string, history []Message) (string, error) {
	if strings.EqualFold(c.cfg.Provider, ProviderAnthropic) {
		return c.anthropicChat(ctx, system, history)
	}
	return c.openaiChat(ctx, system, history)
}

func (c *Client) openaiChat(ctx context.Context, system string, history []Message) (string, error) {
	msgs := make([]chatMessage, 0, len(history)+1)
	if strings.TrimSpace(system) != "" {
		msgs = append(msgs, chatMessage{Role: "system", Content: system})
	}
	for _, m := range history {
		role := m.Role
		if role != "user" && role != "assistant" {
			role = "user"
		}
		msgs = append(msgs, chatMessage{Role: role, Content: m.Content})
	}

	body, err := json.Marshal(chatRequest{
		Model:       c.cfg.Model,
		Temperature: 0.2,
		Messages:    msgs,
	})
	if err != nil {
		return "", err
	}

	endpoint := strings.TrimRight(c.cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)

	data, err := c.do(req)
	if err != nil {
		return "", err
	}

	var cr chatResponse
	if err := json.Unmarshal(data, &cr); err != nil {
		return "", fmt.Errorf("ai: decode response: %w", err)
	}
	if cr.Error != nil {
		return "", fmt.Errorf("ai: %s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return "", errors.New("ai: empty response")
	}
	return strings.TrimSpace(cr.Choices[0].Message.Content), nil
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicResponse struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

func (c *Client) anthropicChat(ctx context.Context, system string, history []Message) (string, error) {
	msgs := make([]anthropicMessage, 0, len(history))
	for _, m := range history {
		role := m.Role
		if role != "user" && role != "assistant" {
			role = "user"
		}
		msgs = append(msgs, anthropicMessage{Role: role, Content: m.Content})
	}

	body, err := json.Marshal(anthropicRequest{
		Model:     c.cfg.Model,
		MaxTokens: 2048,
		System:    system,
		Messages:  msgs,
	})
	if err != nil {
		return "", err
	}

	endpoint := strings.TrimRight(c.cfg.BaseURL, "/") + "/v1/messages"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.cfg.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	data, err := c.do(req)
	if err != nil {
		return "", err
	}

	var ar anthropicResponse
	if err := json.Unmarshal(data, &ar); err != nil {
		return "", fmt.Errorf("ai: decode response: %w", err)
	}
	if ar.Error != nil {
		return "", fmt.Errorf("ai: %s", ar.Error.Message)
	}
	var b strings.Builder
	for _, block := range ar.Content {
		if block.Type == "text" {
			b.WriteString(block.Text)
		}
	}
	if b.Len() == 0 {
		return "", errors.New("ai: empty response")
	}
	return strings.TrimSpace(b.String()), nil
}

// do executes the request and returns the body for a 2xx response.
func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ai: http %d: %s", resp.StatusCode, truncate(string(data), 300))
	}
	return data, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
