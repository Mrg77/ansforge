package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/Mrg77/ansforge/internal/agent"
	"github.com/Mrg77/ansforge/internal/anthropic"
	"github.com/Mrg77/ansforge/internal/guard"
	"github.com/Mrg77/ansforge/internal/report"
	"github.com/Mrg77/ansforge/internal/tools"
	"github.com/Mrg77/ansforge/internal/trace"
)

// runFix repairs what the deterministic rules found, then re-checks.
//
// Headless on purpose: no prompt, no TTY, so it can run unattended. That makes
// the guard the only thing standing between the agent and a machine, which is
// why its toolset excludes every action that touches one — it may read, write
// files and re-scan, and nothing else. A fix is not a deploy.
func runFix(args []string) int {
	fs := flag.NewFlagSet("fix", flag.ExitOnError)
	failOn := fs.String("fail-on", "high", "Exit 1 when a finding at this severity or above SURVIVES the fix.")
	showDiff := fs.Bool("diff", false, "Print `git diff` of what was changed.")
	maxTurns := fs.Int("max-turns", 25, "Bound the agent loop.")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `ansforge fix — repair findings, then re-check.

Usage:
  ansforge fix [path] [flags]

The agent may read and write files and re-run the scan. It cannot run a
playbook: repairing code and changing a machine are different acts.

Flags:`)
		fs.PrintDefaults()
	}
	rest := report.ParseArgs(fs, args)
	path := "."
	if len(rest) > 0 {
		path = rest[0]
	}

	wd, _ := os.Getwd()
	tools.SetProjectRoot(wd)

	before, err := tools.Scan(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ansforge fix:", err)
		return 2
	}
	if len(before) == 0 {
		fmt.Println("nothing to fix — the scan is clean.")
		return 0
	}
	fmt.Printf("ansforge fix · %d finding(s) to work through\n\n", len(before))

	client, err := anthropic.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ansforge fix:", err)
		return 2
	}

	// Deliberately narrow: read, write, verify. No playbook_run, no
	// idempotence_check — an unattended agent does not get to touch a host.
	toolset := []tools.Tool{
		tools.ReadFileTool{},
		tools.WriteFileTool{},
		tools.EditFileTool{},
		tools.SecurityScanTool{},
		tools.LintTool{},
		tools.SyntaxTool{},
		tools.RenderTemplateTool{},
	}

	// No approver: with no human present, a "confirm" decision must fail closed.
	g := guard.New(guard.Default(), nil)

	tr, err := trace.New(client.Model(), auditLogPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "ansforge fix:", err)
		return 2
	}
	defer tr.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ag := agent.New(client, fixPrompt, toolset, g, tr, os.Stdout)
	if v := os.Getenv("ANSFORGE_MAX_COST"); v != "" {
		if usd, err := strconv.ParseFloat(v, 64); err == nil && usd > 0 {
			ag.SetBudget(usd)
		}
	}

	task := fmt.Sprintf("Fix the security findings in %q. Run security_scan first to see them, "+
		"fix what you can safely fix, then run security_scan again to confirm. Leave anything "+
		"you cannot fix safely and say why.", path)
	runErr := ag.Run(ctx, task, *maxTurns)
	fmt.Fprintln(os.Stderr, "\n"+tr.Summary())
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "ansforge fix:", runErr)
	}

	// Re-check independently of whatever the agent claims: the deterministic
	// rules decide whether the fix worked, not the model's own account of it.
	after, err := tools.Scan(path)
	if err != nil {
		return 2
	}
	r := &report.Report{Tool: "ansforge fix", Subject: path, Findings: after,
		Scanned: fmt.Sprintf("%d finding(s) before · %d after", len(before), len(after))}
	fmt.Print(r.Text(0))

	if *showDiff {
		// What actually changed on disk, from git rather than from the agent's
		// own account of its work.
		cmd := exec.CommandContext(ctx, "git", "diff", "--stat")
		cmd.Dir = wd
		if out, err := cmd.CombinedOutput(); err == nil && len(out) > 0 {
			fmt.Printf("\nchanges on disk:\n%s\n", out)
		}
	}
	return r.ExitCode(report.Severity(*failOn))
}

const fixPrompt = `You are ansforge in unattended fix mode. You repair Ansible content that a
deterministic scanner has flagged, and you prove the repair by re-running the scanner.

Work one finding at a time:
  1. read_file the file before editing it, so your edit matches exactly.
  2. edit_file for a surgical change; write_file only for a new file.
  3. After each fix, run security_scan again to confirm the finding is gone.

What a correct fix looks like here:
  - a hard-coded credential moves to Ansible Vault or a lookup, never stays in the file;
  - a task handling a credential gets no_log: true;
  - get_url gets a pinned checksum — if you do not know the real sha256, say so and leave
    it, because an invented checksum is worse than a missing one;
  - shell interpolation gets the | quote filter;
  - a world-writable mode drops the write bit for others.

Rules you do not break:
  - Never invent a value you cannot verify — a checksum, a version, a hostname. Say you
    could not determine it and leave the finding.
  - Never widen the change beyond the finding. You are not here to refactor.
  - If a finding is a deliberate choice (become at play level in a playbook that genuinely
    needs root throughout), leave it and explain why, rather than making the code worse to
    satisfy a rule.
  - You cannot run a playbook. Do not ask.

Finish with a short list: what you fixed, and what you left with the reason.`
