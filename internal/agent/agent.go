// Package agent is THE agentic loop — the ~100 lines that demystify how an AI
// agent (like Claude Code) actually works. There is no framework here on
// purpose: you send messages + tools, the model asks to call a tool, you gate
// it, run it, feed the result back, and loop until the model is done.
//
//	user task ─▶ [ model ] ─▶ text? ──▶ done
//	                │
//	                └─▶ tool_use ─▶ [ GUARD ] ─▶ allow ─▶ run tool ─▶ result ─┐
//	                                    │                                     │
//	                                    └─▶ deny ─▶ denial message ───────────┤
//	                                                                          │
//	                    ◀────────────────── loop with the result ────────────┘
//
// The GUARD step is tfforge's differentiator: unlike a plain "agent that runs
// terraform", every destructive action is checked against policy before it can
// touch anything, and every decision is traced.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Mrg77/ansforge/internal/anthropic"
	"github.com/Mrg77/ansforge/internal/tools"
)

// Decision is what a Guard returns for a proposed tool call.
type Decision int

const (
	Allow   Decision = iota // run it
	Confirm                 // ask the human first (handled by the guard impl)
	Deny                    // refuse; tell the model why
)

// Guard decides whether a tool call may run, given the tool and its raw input.
// It returns a Decision and a human/model-readable reason. Making this an
// interface keeps the loop independent of the policy engine (we plug opsforge's
// policy-as-code behind it next).
type Guard interface {
	Check(t tools.Tool, input json.RawMessage) (Decision, string)
}

// Tracer records what the agent did — the audit trail + cost accounting that
// make an agent reviewable and its spend visible (a real LLMOps concern). A
// no-op tracer is fine for a bare run.
type Tracer interface {
	// Turn records one model round-trip's token usage.
	Turn(inputTokens, outputTokens int)
	// ToolCall records a tool invocation and the guard's decision on it.
	ToolCall(tool string, danger tools.Danger, decision, reason string)
	// Cost returns the estimated USD spend so far — used to enforce a budget.
	Cost() float64
}

// LLM is the single primitive the loop needs from a model client: send
// messages + tools, get a response. anthropic.Client satisfies it, and tests
// swap in a fake so the loop is verifiable without spending tokens.
type LLM interface {
	CreateMessage(ctx context.Context, system string, messages []anthropic.Message, tools []anthropic.Tool) (*anthropic.Response, error)
}

// Agent wires the model, the tools, the guard and the tracer together.
type Agent struct {
	client  LLM
	system  string
	tools   []tools.Tool
	byName  map[string]tools.Tool
	guard   Guard
	tracer  Tracer
	out     io.Writer // where assistant text is streamed to the user
	maxCost float64   // 0 = no budget; else stop before exceeding it
}

// SetBudget caps the run's estimated spend. When the tracer's cost reaches this
// ceiling, Run stops with a clear error instead of billing further — the
// "FinOps of agents" control (a real LLMOps concern).
func (a *Agent) SetBudget(usd float64) { a.maxCost = usd }

// New builds an agent. guard/tracer may be nil (defaults: allow-all / no-op) —
// but tfforge always wires real ones; nil is only for the barest first demo.
func New(c LLM, system string, ts []tools.Tool, g Guard, tr Tracer, out io.Writer) *Agent {
	if g == nil {
		g = allowAll{}
	}
	if tr == nil {
		tr = noopTracer{}
	}
	return &Agent{
		client: c,
		system: system,
		tools:  ts,
		byName: tools.ByName(ts),
		guard:  g,
		tracer: tr,
		out:    out,
	}
}

// Run drives the loop for one user task until the model stops asking for tools.
// maxTurns bounds it so a misbehaving model can't loop forever (a real
// reliability concern for agents in production).
func (a *Agent) Run(ctx context.Context, task string, maxTurns int) error {
	messages := []anthropic.Message{
		{Role: "user", Content: []anthropic.ContentBlock{{Type: "text", Text: task}}},
	}
	defs := tools.Definitions(a.tools)

	for turn := 0; turn < maxTurns; turn++ {
		resp, err := a.client.CreateMessage(ctx, a.system, messages, defs)
		if err != nil {
			return err
		}
		a.tracer.Turn(resp.Usage.InputTokens, resp.Usage.OutputTokens)

		// Budget guard: if this run has reached its cost ceiling, stop cleanly
		// rather than keep billing. Checked after recording the turn so the spend
		// is accurate in the summary.
		if a.maxCost > 0 && a.tracer.Cost() >= a.maxCost {
			return fmt.Errorf("stopped: reached the cost budget of $%.2f (spent ~$%.4f). Raise TFFORGE_MAX_COST or simplify the task", a.maxCost, a.tracer.Cost())
		}

		// Echo any assistant text, and collect tool_use blocks to run.
		var toolUses []anthropic.ContentBlock
		for _, block := range resp.Content {
			switch block.Type {
			case "text":
				if block.Text != "" {
					fmt.Fprintln(a.out, block.Text)
				}
			case "tool_use":
				toolUses = append(toolUses, block)
			}
		}

		// The model is done when it requested no tools. We gate on the presence
		// of tool_use blocks, NOT on StopReason == "tool_use": if the model emits
		// a tool_use block but the turn ends on "max_tokens" (truncated) or
		// "pause_turn", the blocks are still there and must be run — checking
		// StopReason alone would silently drop them and end the task as "done".
		if len(toolUses) == 0 {
			return nil
		}

		// Record the assistant turn (with its tool_use blocks) in the history.
		messages = append(messages, anthropic.Message{Role: "assistant", Content: resp.Content})

		// Run each requested tool through the guard, gather results.
		var results []anthropic.ContentBlock
		for _, tu := range toolUses {
			results = append(results, a.handleToolUse(ctx, tu))
		}
		messages = append(messages, anthropic.Message{Role: "user", Content: results})
	}
	return fmt.Errorf("stopped after %d turns without completing (possible loop)", maxTurns)
}

// handleToolUse gates one tool call, runs it if allowed, and returns the
// tool_result block to send back to the model.
func (a *Agent) handleToolUse(ctx context.Context, tu anthropic.ContentBlock) anthropic.ContentBlock {
	result := func(text string, isErr bool) anthropic.ContentBlock {
		return anthropic.ContentBlock{Type: "tool_result", ToolUseID: tu.ID, Content: text, IsError: isErr}
	}

	t, ok := a.byName[tu.Name]
	if !ok {
		return result(fmt.Sprintf("unknown tool %q", tu.Name), true)
	}

	// THE GUARD STEP — the differentiator.
	decision, reason := a.guard.Check(t, tu.Input)
	a.tracer.ToolCall(tu.Name, t.Danger(), decisionString(decision), reason)
	if decision == Deny {
		// Tell the model why, so it can adapt instead of retrying blindly.
		return result(fmt.Sprintf("BLOCKED by policy: %s. Do not retry this action; propose a safer alternative or ask the user.", reason), true)
	}

	out, err := t.Run(ctx, tu.Input)
	if err != nil {
		// Return the tool's output too — terraform's diagnostics are useful to the model.
		msg := err.Error()
		if out != "" {
			msg += "\n\n" + out
		}
		return result(msg, true)
	}
	return result(out, false)
}

func decisionString(d Decision) string {
	switch d {
	case Deny:
		return "deny"
	case Confirm:
		return "confirm"
	default:
		return "allow"
	}
}

// --- default no-op wiring (only for the barest first demo) ------------------

type allowAll struct{}

func (allowAll) Check(tools.Tool, json.RawMessage) (Decision, string) {
	return Allow, "no guard configured"
}

type noopTracer struct{}

func (noopTracer) Turn(int, int)                                 {}
func (noopTracer) ToolCall(string, tools.Danger, string, string) {}
func (noopTracer) Cost() float64                                 { return 0 }
