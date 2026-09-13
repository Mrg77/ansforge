// Command ansforge is an AI agent that BUILDS, validates, and secures Ansible —
// by running it, not by reading it.
//
// ansible-lint validates form. It cannot tell you that a template references a
// variable that will not exist on the host, that a config is syntactically
// valid but rejected by the daemon that consumes it, or that a playbook reports
// "changed" forever because a task lacks changed_when. ansforge closes that gap:
// it renders templates THROUGH Ansible, validates the result with the upstream
// tool inside a container, and checks idempotence by playing twice.
//
// Every action that touches a real machine passes through policy-as-code, so the
// agent can help without being able to converge production by accident.
//
// Usage:
//
//	export ANTHROPIC_API_KEY=...   # from console.anthropic.com (billed per token)
//	ansforge "review roles/nginx, render its templates and fix what breaks"
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Mrg77/ansforge/internal/agent"
	"github.com/Mrg77/ansforge/internal/anthropic"
	"github.com/Mrg77/ansforge/internal/guard"
	"github.com/Mrg77/ansforge/internal/tools"
	"github.com/Mrg77/ansforge/internal/trace"
)

var version = "dev"

const systemPrompt = `You are ansforge, an AI agent that writes, validates and secures
Ansible for a DevOps engineer — and proves its work by running it.

Your guiding principle: ansible-lint validates FORM, execution validates BEHAVIOUR.
Never report a change as done because the lint is green.

When asked to build or fix Ansible content, follow this loop until it is clean:

  1. READ — read_file the existing content before editing it, so an edit matches exactly.
  2. WRITE — write_file for a new file, edit_file for a surgical change (far cheaper
     than rewriting).
  3. LINT — ansible_lint (production profile) and ansible_syntax. Necessary, never
     sufficient.
  4. RENDER — for every template you touched, render_template. This renders THROUGH
     Ansible with the real variables. A Jinja2 test that supplies variables by hand
     hides the exact bugs this catches:
       - ansible_managed only exists in the template module, not in copy's content:
       - magic variables (inventory_hostname, ansible_facts) do not exist in a bare render
     Pass the project's group_vars and role defaults as var_files.
  5. VALIDATE — validate_rendered on the output, with the tool that will consume it
     (nginx -t, promtool, amtool, logrotate). Valid YAML is not an accepted config.
  6. SECURE — security_scan. Fix the high findings; justify anything you leave.
  7. VERIFY BEHAVIOUR — when an inventory is available, playbook_check first. Use
     idempotence_check when the playbook will be replayed by a convergence mechanism.

Rules you always apply when writing Ansible:
  - Fully-qualified module names (ansible.builtin.copy, not copy).
  - no_log: true on any task handling a credential — Ansible logs module args by default.
  - Never a plain-text secret: Vault or an external store, referenced by lookup.
  - get_url always with a pinned checksum; bump version and checksum together.
  - command/shell only when no module fits, and always with the | quote filter on
    interpolated variables.
  - become on the tasks that need it, not on the whole play.
  - Every task named, in the imperative, describing intent.
  - changed_when / creates on anything that would otherwise always report changed.

Honesty rules:
  - If a tool could not run (ansible absent, no docker), SAY the check did not happen.
    Never let silence read as success.
  - When you fix a finding, re-run the check that found it. A fix is not a fix until
    the check passes.
  - State plainly what you did not verify.`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, `ansforge — an AI agent that builds, validates and secures Ansible.

Usage:
  ansforge "<task>"          run the agent on a task
  ansforge scan [path]       gate one scope — deterministic, no API key, exits 1 on a high finding
  ansforge audit [path]      report a whole tree — deterministic, report-only by default
  ansforge fix [path]        fix findings, then re-check (costs tokens)
  ansforge version

Shared flags on scan/audit/fix:
  --json                     machine-readable, for aggregation
  --html [--out FILE]        self-contained HTML report (no JavaScript)
  --explain                  add prose and a real before/after per finding (costs tokens)
  --fail-on <severity>       critical | high | medium | low | info | none
  --top N                    show only the N worst problems

Environment:
  ANTHROPIC_API_KEY          required for agent runs
  ANSFORGE_MODEL             override the model
  ANSFORGE_MAX_COST          stop before exceeding this spend, in USD
  ANSFORGE_AUDIT             audit log path, or "off"

Examples:
  ansforge scan .                       # the CI gate
  ansforge audit . --html --out health.html
  ansforge audit . --explain            # with before/after diffs
  ansforge fix . --diff                 # repair, then re-check
  ansforge "render roles/nginx templates with group_vars/all and fix what breaks"`)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println("ansforge", version)
		return
	// The family contract, identical in tfforge and ciforge: scan gates one
	// scope, audit reports a tree, fix repairs and re-checks. The first two are
	// deterministic and free; fix and the bare agent call a model.
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "audit":
		os.Exit(runAudit(os.Args[2:]))
	case "fix":
		os.Exit(runFix(os.Args[2:]))
	}

	task := strings.Join(os.Args[1:], " ")

	client, err := anthropic.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ansforge:", err)
		os.Exit(1)
	}

	// Confine every path the model supplies to the working directory: it may
	// build a role, never read /etc or escape through "..".
	if wd, err := os.Getwd(); err == nil {
		tools.SetProjectRoot(wd)
	}

	toolset := []tools.Tool{
		tools.ReadFileTool{},         // look before editing
		tools.WriteFileTool{},        // create
		tools.EditFileTool{},         // surgical fix
		tools.LintTool{},             // form
		tools.SyntaxTool{},           // parse, including roles
		tools.RenderTemplateTool{},   // the differentiator: render through Ansible
		tools.ValidateRenderedTool{}, // the upstream tool judges the result
		tools.SecurityScanTool{},     // Ansible-specific weaknesses
		tools.PlaybookCheckTool{},    // dry run
		tools.PlaybookRunTool{},      // guarded: changes real machines
		tools.IdempotenceTool{},      // guarded: plays twice
	}

	// Policy-as-code. The default denies a real playbook run against production
	// and confirms it elsewhere. With no TTY, "confirm" fails safe to deny.
	g := guard.New(guard.Default(), ttyConfirm)

	tr, err := trace.New(client.Model(), auditLogPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "ansforge: could not open audit log:", err)
		os.Exit(1)
	}
	defer tr.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ag := agent.New(client, systemPrompt, toolset, g, tr, os.Stdout)

	if v := os.Getenv("ANSFORGE_MAX_COST"); v != "" {
		if usd, err := strconv.ParseFloat(v, 64); err == nil && usd > 0 {
			ag.SetBudget(usd)
		}
	}

	fmt.Printf("ansforge · model %s\n\n", client.Model())
	runErr := ag.Run(ctx, task, 30)

	fmt.Fprintln(os.Stderr, "\n"+tr.Summary())
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "ansforge:", runErr)
		os.Exit(1)
	}
}

func auditLogPath() string {
	switch v := os.Getenv("ANSFORGE_AUDIT"); v {
	case "off", "0", "false":
		return ""
	case "":
		return trace.DefaultLogPath()
	default:
		return v
	}
}

// ttyConfirm asks the human to approve a guarded action. Without a terminal
// (CI, a pipe) it returns false — never auto-approve something that changes a
// machine.
func ttyConfirm(action, ctx, message string) bool {
	fmt.Fprintf(os.Stderr, "\n⚠  The agent wants to run: %s", action)
	if ctx != "" {
		fmt.Fprintf(os.Stderr, "  (context: %s)", ctx)
	}
	fmt.Fprintf(os.Stderr, "\n   %s\n   Proceed? [y/N] ", message)

	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(sc.Text()))
	return answer == "y" || answer == "yes"
}
