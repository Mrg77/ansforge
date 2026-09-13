// Package tools defines the actions tfforge exposes to the agent, and the
// contract every tool implements. Each tool declares its JSON schema (so the
// model knows how to call it) and a Danger level (so the guard knows how hard
// to think before letting it run). Keeping Danger on the tool itself — not
// buried in the guard — is what makes the safety layer auditable.
package tools

import (
	"context"
	"encoding/json"

	"github.com/Mrg77/ansforge/internal/anthropic"
)

// Danger classifies what a tool can do, so the guard can gate destructive
// actions without re-parsing intent. Read-only tools flow freely; mutating and
// destructive ones go through policy.
type Danger int

const (
	ReadOnly    Danger = iota // plan, show, analyze — cannot change infra
	Mutating                  // apply — creates/updates real resources
	Destructive               // destroy — tears infra down
)

func (d Danger) String() string {
	switch d {
	case Mutating:
		return "mutating"
	case Destructive:
		return "destructive"
	default:
		return "read-only"
	}
}

// Tool is one action the agent can take. Name/Description/Schema become the
// tool definition sent to the model; Run executes it with the model-provided
// input (raw JSON, so each tool decodes its own args).
type Tool interface {
	Name() string
	Description() string
	Schema() map[string]any
	Danger() Danger
	Run(ctx context.Context, input json.RawMessage) (string, error)
}

// Definitions turns a tool set into the API's tool-definition list.
func Definitions(ts []Tool) []anthropic.Tool {
	out := make([]anthropic.Tool, 0, len(ts))
	for _, t := range ts {
		out = append(out, anthropic.Tool{
			Name:        t.Name(),
			Description: t.Description(),
			InputSchema: t.Schema(),
		})
	}
	return out
}

// ByName indexes a tool set for the agent loop's dispatch.
func ByName(ts []Tool) map[string]Tool {
	m := make(map[string]Tool, len(ts))
	for _, t := range ts {
		m[t.Name()] = t
	}
	return m
}
