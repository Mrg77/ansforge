// Package anthropic is a from-scratch client for the Anthropic Messages API,
// written in raw HTTP on purpose: the whole point of tfforge is to SEE how an
// agent works under the hood, not hide it behind an SDK. It implements exactly
// what an agent loop needs — sending messages + tool definitions, and reading
// back either text or a tool-use request.
//
// The API contract (Messages API): you POST a list of messages and a list of
// tools. The model replies with `content` blocks that are either {type:"text"}
// or {type:"tool_use", name, input}. When it wants a tool, you run it and send
// the result back as a {type:"tool_result"} block in a new user message, then
// call again. That loop IS the agent. See internal/agent for the loop itself.
package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	defaultBaseURL = "https://api.anthropic.com/v1/messages"
	apiVersion     = "2023-06-01"
	// Default model: Sonnet 4.5 — a strong, cost-efficient choice for an agent
	// that makes many tool-use round trips (you pay per token). Override with
	// TFFORGE_MODEL, e.g. claude-opus-4-8 for the most capable reasoning.
	defaultModel = "claude-sonnet-4-5"
)

// Client talks to the Messages API. Zero value is not usable; use New.
type Client struct {
	apiKey    string
	baseURL   string
	model     string
	http      *http.Client
	maxTokens int
}

// defaultMaxTokens bounds a single response. 4096 suits the agent's tool-use
// turns, but batch jobs (e.g. `audit --explain` over many findings) need more
// headroom or the JSON reply gets truncated at the cap — see SetMaxTokens.
const defaultMaxTokens = 4096

// SetMaxTokens overrides the per-response token cap for this client. Callers that
// expect a large single reply (a batch of explanations) raise it so the response
// isn't cut off mid-JSON.
func (c *Client) SetMaxTokens(n int) {
	if n > 0 {
		c.maxTokens = n
	}
}

// New builds a client from $ANTHROPIC_API_KEY (the API key is billed per token,
// and is distinct from a Claude.ai subscription). Returns an error if unset, so
// the agent fails fast with a clear message instead of a cryptic 401.
func New() (*Client, error) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY is not set — create one at https://console.anthropic.com (billed per token, separate from a Claude subscription)")
	}
	model := defaultModel
	if m := os.Getenv("TFFORGE_MODEL"); m != "" {
		model = m
	}
	return &Client{
		apiKey:    key,
		baseURL:   defaultBaseURL,
		model:     model,
		http:      &http.Client{Timeout: 120 * time.Second},
		maxTokens: defaultMaxTokens,
	}, nil
}

// Model returns the model this client is configured to use.
func (c *Client) Model() string { return c.model }

// --- wire types: exactly the shape the Messages API expects/returns ---------

// Tool is a tool definition advertised to the model. InputSchema is a JSON
// Schema object describing the tool's parameters.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

// Message is one turn. Role is "user" or "assistant". Content is a list of
// blocks (text / tool_use / tool_result), which is what makes multi-tool
// turns possible.
type Message struct {
	Role    string         `json:"role"`
	Content []ContentBlock `json:"content"`
}

// ContentBlock is a polymorphic block. Only the fields relevant to its Type are
// set; JSON omitempty keeps the payload valid for each variant.
type ContentBlock struct {
	Type string `json:"type"`

	// type=text
	Text string `json:"text,omitempty"`

	// type=tool_use (model → us)
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`

	// type=tool_result (us → model)
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   string `json:"content,omitempty"`
	IsError   bool   `json:"is_error,omitempty"`
}

// request is the POST body.
type request struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []Message `json:"messages"`
	Tools     []Tool    `json:"tools,omitempty"`
}

// Response is the subset of the API response the agent loop needs.
type Response struct {
	Content    []ContentBlock `json:"content"`
	StopReason string         `json:"stop_reason"` // "end_turn" | "tool_use" | ...
	Usage      Usage          `json:"usage"`
}

// Usage carries token counts, so the agent can report cost (a real LLMOps concern).
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// apiError is the API's error envelope.
type apiError struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// CreateMessage sends one request and returns the model's response. This is the
// single primitive the agent loop calls repeatedly.
func (c *Client) CreateMessage(ctx context.Context, system string, messages []Message, tools []Tool) (*Response, error) {
	maxTok := c.maxTokens
	if maxTok <= 0 {
		maxTok = defaultMaxTokens
	}
	body, err := json.Marshal(request{
		Model:     c.model,
		MaxTokens: maxTok,
		System:    system,
		Messages:  messages,
		Tools:     tools,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", apiVersion)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling Anthropic API: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var ae apiError
		if json.Unmarshal(data, &ae) == nil && ae.Error.Message != "" {
			return nil, fmt.Errorf("Anthropic API %d: %s", resp.StatusCode, ae.Error.Message)
		}
		return nil, fmt.Errorf("Anthropic API %d: %s", resp.StatusCode, string(data))
	}

	var out Response
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &out, nil
}
