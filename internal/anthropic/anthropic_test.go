package anthropic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The model name is a wire value: a typo is not a compile error, it is a 404 at
// the first real call. This pins what actually leaves the process.
func TestDefaultModelReachesTheWire(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "test-key")
	t.Setenv("ANSFORGE_MODEL", "")

	var got struct {
		Model string `json:"model"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("request body is not valid JSON: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	defer srv.Close()

	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.baseURL = srv.URL

	if c.Model() != defaultModel {
		t.Fatalf("Model() = %q, want the default %q", c.Model(), defaultModel)
	}
	if _, err := c.CreateMessage(context.Background(), "sys", []Message{{Role: "user", Content: []ContentBlock{{Type: "text", Text: "hi"}}}}, nil); err != nil {
		t.Fatalf("CreateMessage: %v", err)
	}
	if got.Model != defaultModel {
		t.Errorf("model on the wire = %q, want %q", got.Model, defaultModel)
	}
}

// An override must win, so a user can drop to Haiku or up to Opus per run.
func TestModelOverrideWins(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "test-key")
	t.Setenv("ANSFORGE_MODEL", "claude-opus-5")

	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Model() != "claude-opus-5" {
		t.Errorf("Model() = %q, want the override", c.Model())
	}
}
