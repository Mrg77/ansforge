package guard

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Mrg77/ansforge/internal/agent"
	"github.com/Mrg77/ansforge/internal/tools"
)

// stubTool is a minimal tool with a chosen name and danger level, so the guard
// can be driven without running Ansible.
type stubTool struct {
	name   string
	danger tools.Danger
}

func (s stubTool) Name() string                                         { return s.name }
func (s stubTool) Description() string                                  { return "" }
func (s stubTool) Schema() map[string]any                               { return nil }
func (s stubTool) Danger() tools.Danger                                 { return s.danger }
func (s stubTool) Run(context.Context, json.RawMessage) (string, error) { return "", nil }

// input builds the tool input the guard inspects to detect the context.
func input(inventory, playbook, limit string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{
		"inventory": inventory, "playbook": playbook, "limit": limit,
	})
	return b
}

func alwaysConfirm(_, _, _ string) bool { return true }
func neverConfirm(_, _, _ string) bool  { return false }

// TestProdRunIsDenied is the headline behaviour: the agent cannot converge
// production, and no approver can override a DENY.
func TestProdRunIsDenied(t *testing.T) {
	g := New(Default(), alwaysConfirm) // even a yes-man approver must not override deny
	run := stubTool{name: "playbook_run", danger: tools.Destructive}

	d, reason := g.Check(run, input("inventories/prod/hosts.yml", "site.yml", ""))
	if d != agent.Deny {
		t.Fatalf("a real run against a prod inventory must be DENIED, got %v (%s)", d, reason)
	}
}

// TestProdDetectedFromLimit — the environment often lives in the host pattern
// rather than the inventory path.
func TestProdDetectedFromLimit(t *testing.T) {
	g := New(Default(), alwaysConfirm)
	run := stubTool{name: "playbook_run", danger: tools.Destructive}

	d, _ := g.Check(run, input("hosts.yml", "site.yml", "prod-web-*"))
	if d != agent.Deny {
		t.Fatalf("a prod host pattern must be DENIED, got %v", d)
	}
}

// TestRealRunNeedsApproval — outside production a real run is still a change to
// real machines, so it needs a human.
func TestRealRunNeedsApproval(t *testing.T) {
	g := New(Default(), neverConfirm)
	run := stubTool{name: "playbook_run", danger: tools.Destructive}

	d, _ := g.Check(run, input("inventories/dev/hosts.yml", "site.yml", ""))
	if d == agent.Allow {
		t.Fatal("a real run must not proceed without approval")
	}

	g = New(Default(), alwaysConfirm)
	if d, _ := g.Check(run, input("inventories/dev/hosts.yml", "site.yml", "")); d != agent.Allow {
		t.Fatalf("a real run on dev with approval should be allowed, got %v", d)
	}
}

// TestCheckModeFlowsOutsideProd — check mode changes nothing, so rehearsing must
// not require ceremony. A guard that blocks the safe path pushes people around it.
func TestCheckModeFlowsOutsideProd(t *testing.T) {
	g := New(Default(), neverConfirm)
	check := stubTool{name: "playbook_check", danger: tools.Mutating}

	d, _ := g.Check(check, input("inventories/dev/hosts.yml", "site.yml", ""))
	if d != agent.Allow {
		t.Fatalf("check mode outside prod should be allowed, got %v", d)
	}
}

// TestCheckModeOnProdConfirms — check mode changes nothing but still connects to
// production hosts, which is worth a prompt.
func TestCheckModeOnProdConfirms(t *testing.T) {
	g := New(Default(), neverConfirm)
	check := stubTool{name: "playbook_check", danger: tools.Mutating}

	if d, _ := g.Check(check, input("inventories/prod/hosts.yml", "site.yml", "")); d == agent.Allow {
		t.Fatal("check mode against prod should require approval")
	}
}

// TestReadOnlyAlwaysAllowed — a misconfigured policy must never stop the agent
// from merely looking.
func TestReadOnlyAlwaysAllowed(t *testing.T) {
	g := New(Default(), neverConfirm)
	for _, name := range []string{"ansible_lint", "render_template", "security_scan", "read_file"} {
		ro := stubTool{name: name, danger: tools.ReadOnly}
		if d, _ := g.Check(ro, input("inventories/prod/hosts.yml", "site.yml", "")); d != agent.Allow {
			t.Fatalf("read-only tool %q must always be allowed, got %v", name, d)
		}
	}
}

// TestEmptyPolicyFallsBackToDefault — a blank policy file must not silently
// disable the guard. Fail-safe beats fail-open.
func TestEmptyPolicyFallsBackToDefault(t *testing.T) {
	g := New(&Policy{Version: 1}, alwaysConfirm)
	run := stubTool{name: "playbook_run", danger: tools.Destructive}

	if d, _ := g.Check(run, input("inventories/prod/hosts.yml", "site.yml", "")); d != agent.Deny {
		t.Fatalf("an empty policy must fall back to the default and deny prod, got %v", d)
	}
}

// TestUnknownContextFailsClosed — when the context cannot be determined, a
// destructive action must not slip through unguarded.
func TestUnknownContextFailsClosed(t *testing.T) {
	g := New(Default(), neverConfirm)
	run := stubTool{name: "playbook_run", danger: tools.Destructive}

	if d, _ := g.Check(run, input("", "", "")); d == agent.Allow {
		t.Fatal("an unknown context must not allow a destructive action without approval")
	}
}

// TestIdempotenceCheckIsGated — it plays the playbook for real, twice. The name
// sounds like a test; the effect is a convergence.
func TestIdempotenceCheckIsGated(t *testing.T) {
	g := New(Default(), neverConfirm)
	idem := stubTool{name: "idempotence_check", danger: tools.Destructive}

	if d, _ := g.Check(idem, input("inventories/prod/hosts.yml", "site.yml", "")); d == agent.Allow {
		t.Fatal("idempotence_check runs for real and must be gated")
	}
}
