package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteFileTool creates or replaces a file. Mutating, and confined to the
// project root — the agent can build a role, never touch /etc.
type WriteFileTool struct{}

func (WriteFileTool) Name() string   { return "write_file" }
func (WriteFileTool) Danger() Danger { return Mutating }
func (WriteFileTool) Description() string {
	return "Create or overwrite a file with the given content. Use for a new playbook, role file " +
		"or template; prefer edit_file when only part of an existing file changes."
}
func (WriteFileTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path":    map[string]any{"type": "string", "description": "File path (relative to the project)."},
			"content": map[string]any{"type": "string", "description": "Full file content."},
		},
		"required":             []string{"path", "content"},
		"additionalProperties": false,
	}
}

func (WriteFileTool) Run(_ context.Context, input json.RawMessage) (string, error) {
	var in struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	if in.Path == "" {
		return "", fmt.Errorf("path is required")
	}
	p, err := confine(in.Path)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, []byte(in.Content), 0o644); err != nil {
		return "", err
	}
	return fmt.Sprintf("wrote %s (%d bytes)", in.Path, len(in.Content)), nil
}

// EditFileTool does a surgical search/replace. Cheaper than rewriting a whole
// file, and safer: `old` must occur exactly once, so a fix can never land in
// the wrong place.
type EditFileTool struct{}

func (EditFileTool) Name() string   { return "edit_file" }
func (EditFileTool) Danger() Danger { return Mutating }
func (EditFileTool) Description() string {
	return "Replace an exact snippet in an existing file. `old` must appear EXACTLY once; the " +
		"tool errors otherwise, so a fix is never applied to the wrong place."
}
func (EditFileTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "File path (relative to the project)."},
			"old":  map[string]any{"type": "string", "description": "Exact text to replace (must occur exactly once)."},
			"new":  map[string]any{"type": "string", "description": "Replacement text."},
		},
		"required":             []string{"path", "old", "new"},
		"additionalProperties": false,
	}
}

func (EditFileTool) Run(_ context.Context, input json.RawMessage) (string, error) {
	var in struct {
		Path string `json:"path"`
		Old  string `json:"old"`
		New  string `json:"new"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	if in.Path == "" || in.Old == "" {
		return "", fmt.Errorf("path and old are required")
	}
	p, err := confine(in.Path)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", in.Path, err)
	}
	body := string(b)
	if n := strings.Count(body, in.Old); n != 1 {
		return "", fmt.Errorf("`old` occurs %d times in %s — it must occur exactly once; include more surrounding context", n, in.Path)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(body, in.Old, in.New, 1)), 0o644); err != nil {
		return "", err
	}
	return fmt.Sprintf("edited %s", in.Path), nil
}

// ReadFileTool lets the agent look before it edits.
type ReadFileTool struct{}

func (ReadFileTool) Name() string   { return "read_file" }
func (ReadFileTool) Danger() Danger { return ReadOnly }
func (ReadFileTool) Description() string {
	return "Read a file's content. Use before edit_file so the replaced snippet matches exactly."
}
func (ReadFileTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "File path (relative to the project)."},
		},
		"required":             []string{"path"},
		"additionalProperties": false,
	}
}

func (ReadFileTool) Run(_ context.Context, input json.RawMessage) (string, error) {
	var in struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	p, err := confine(in.Path)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", in.Path, err)
	}
	return truncate(string(b), 20000), nil
}
