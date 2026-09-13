// Package trace is tfforge's audit + cost layer — the "LLMOps" concern that
// separates a demo agent from one you'd let near real infrastructure. It records
// every model turn (token usage → cost) and every tool call with the guard's
// decision, to a structured JSONL audit log, and prints a run summary.
//
// Why it matters: an autonomous agent that touches infra must be REVIEWABLE
// ("what did it do, what did it try, what did the guard block?") and its spend
// VISIBLE ("what did this run cost?"). Both are exactly what teams ask for when
// putting agents in production.
package trace

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Mrg77/ansforge/internal/tools"
)

// Pricing is per-million-token USD rates for a model. Approximate and easily
// overridden; the point is order-of-magnitude cost visibility, not billing.
type Pricing struct {
	InputPerM  float64
	OutputPerM float64
}

// modelPricing holds rough public rates. Unknown models fall back to a
// mid-range estimate so cost is never silently zero.
var modelPricing = map[string]Pricing{
	"claude-opus-5":    {InputPerM: 15, OutputPerM: 75},
	"claude-sonnet-5":  {InputPerM: 3, OutputPerM: 15},
	"claude-fable-5-1": {InputPerM: 3, OutputPerM: 15},
	"claude-haiku-4-5": {InputPerM: 1, OutputPerM: 5},
	// Previous generation, still selectable through <TOOL>_MODEL.
	"claude-sonnet-4-5": {InputPerM: 3, OutputPerM: 15},
	"claude-opus-4-8":   {InputPerM: 15, OutputPerM: 75},
}

func priceFor(model string) Pricing {
	if p, ok := modelPricing[model]; ok {
		return p
	}
	return Pricing{InputPerM: 3, OutputPerM: 15} // sensible default
}

// EstimateCost returns the approximate USD cost of a single call with the given
// token counts, using the same rough public rates as the run tracer. Exported so
// one-shot callers (e.g. `audit --explain`) can price their own API call for
// FinOps visibility, without wiring up a full Tracer.
func EstimateCost(model string, inTok, outTok int) float64 {
	p := priceFor(model)
	return float64(inTok)/1e6*p.InputPerM + float64(outTok)/1e6*p.OutputPerM
}

// event is one audit-log line. Timestamps are RFC3339; kind is "turn" or "tool".
type event struct {
	Time     string `json:"time"`
	Kind     string `json:"kind"`
	Model    string `json:"model,omitempty"`
	InTok    int    `json:"input_tokens,omitempty"`
	OutTok   int    `json:"output_tokens,omitempty"`
	Tool     string `json:"tool,omitempty"`
	Danger   string `json:"danger,omitempty"`
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Tracer implements agent.Tracer: it accumulates totals and appends each event
// to an audit log. Safe for concurrent tool calls within a turn.
type Tracer struct {
	mu    sync.Mutex
	model string
	price Pricing
	log   io.Writer // JSONL audit sink (may be nil = no file)
	now   func() time.Time

	turns    int
	inTok    int
	outTok   int
	tools    int
	denied   int
	confirms int
}

// New builds a Tracer for a model. If logPath is non-empty, events are appended
// there as JSONL (created if needed). now defaults to time.Now.
func New(model, logPath string) (*Tracer, error) {
	t := &Tracer{model: model, price: priceFor(model), now: time.Now}
	if logPath != "" {
		if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
		t.log = f
	}
	return t, nil
}

// DefaultLogPath is ~/.local/state/tfforge/audit.jsonl (XDG state dir).
func DefaultLogPath() string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "tfforge", "audit.jsonl")
}

// Turn records a model round-trip's token usage.
func (t *Tracer) Turn(in, out int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.turns++
	t.inTok += in
	t.outTok += out
	t.write(event{Kind: "turn", Model: t.model, InTok: in, OutTok: out})
}

// ToolCall records a tool invocation and the guard's decision.
func (t *Tracer) ToolCall(tool string, danger tools.Danger, decision, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tools++
	switch decision {
	case "deny":
		t.denied++
	case "confirm":
		t.confirms++
	}
	t.write(event{Kind: "tool", Tool: tool, Danger: danger.String(), Decision: decision, Reason: reason})
}

// write appends one JSONL event to the audit log (no-op if no sink).
func (t *Tracer) write(e event) {
	if t.log == nil {
		return
	}
	e.Time = t.now().UTC().Format(time.RFC3339)
	if data, err := json.Marshal(e); err == nil {
		fmt.Fprintln(t.log, string(data))
	}
}

// Cost returns the estimated USD cost of the run so far.
func (t *Tracer) Cost() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return float64(t.inTok)/1e6*t.price.InputPerM + float64(t.outTok)/1e6*t.price.OutputPerM
}

// Summary is a one-block, human-facing recap of the run: turns, tokens, tool
// calls, guard actions, and estimated cost.
func (t *Tracer) Summary() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	cost := float64(t.inTok)/1e6*t.price.InputPerM + float64(t.outTok)/1e6*t.price.OutputPerM
	return fmt.Sprintf(
		"run summary · %d turns · %d in / %d out tokens · %d tool call(s)"+
			" (%d denied, %d confirmed) · ~$%.4f (%s)",
		t.turns, t.inTok, t.outTok, t.tools, t.denied, t.confirms, cost, t.model,
	)
}

// Close closes the audit-log file if one is open.
func (t *Tracer) Close() error {
	if f, ok := t.log.(io.Closer); ok {
		return f.Close()
	}
	return nil
}
