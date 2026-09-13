package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mrg77/ansforge/internal/report"
	"github.com/Mrg77/ansforge/internal/tools"
)

// runScan gates one scope: the deterministic half of the tool. No model, no API
// key, and the same verdict on the same input — which is the only reason it may
// stand in a pipeline. The agent advises; this decides.
func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var o report.Options
	o.Bind(fs, "high")
	fs.Usage = usageFor(fs, "scan", "Deterministic security scan of a path. Exits 1 at --fail-on or above.")

	rest := report.ParseArgs(fs, args)
	path := "."
	if len(rest) > 0 {
		path = rest[0]
	}
	return emit(path, o, false)
}

// runAudit reports the whole tree rather than gating one scope: same checks,
// but report-only by default and with the per-category breakdown that makes the
// HTML tabs. Depth, not a different truth.
func runAudit(args []string) int {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	var o report.Options
	o.Bind(fs, "none")
	fs.Usage = usageFor(fs, "audit", "Prioritised health report of an Ansible tree. Report-only unless --fail-on is given.")

	rest := report.ParseArgs(fs, args)
	path := "."
	if len(rest) > 0 {
		path = rest[0]
	}
	return emit(path, o, true)
}

// emit runs the deterministic rules and renders. Both subcommands share it, so
// scan and audit can never disagree about what a finding is.
func emit(path string, o report.Options, tree bool) int {
	wd, _ := os.Getwd()
	tools.SetProjectRoot(wd)

	findings, err := tools.Scan(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ansforge:", err)
		return 2
	}

	r := &report.Report{
		Tool:     "ansforge",
		Subject:  subjectOf(path),
		Scanned:  scannedSummary(path),
		Findings: findings,
	}

	if o.Explain {
		if err := explain(r); err != nil {
			// A failed explanation must not discard the deterministic findings:
			// the free half of the tool is the half that matters.
			fmt.Fprintln(os.Stderr, "ansforge: --explain failed, reporting without it:", err)
		}
	}
	return r.Emit(o)
}

func subjectOf(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return filepath.Base(abs)
}

// scannedSummary states what was actually looked at, so a report on an empty
// directory cannot be mistaken for a clean bill of health.
func scannedSummary(path string) string {
	var files, dirs int
	root, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil {
			return nil
		}
		if fi.IsDir() {
			switch fi.Name() {
			case ".git", "collections", ".cache", "node_modules", ".venv":
				return filepath.SkipDir
			}
			dirs++
			return nil
		}
		if ext := strings.ToLower(filepath.Ext(p)); ext == ".yml" || ext == ".yaml" || ext == ".cfg" {
			files++
		}
		return nil
	})
	return fmt.Sprintf("scanned %d directory(ies) · %d YAML file(s)", dirs, files)
}

// usageFor keeps every subcommand's help identical in shape across the family.
func usageFor(fs *flag.FlagSet, name, what string) func() {
	return func() {
		fmt.Fprintf(os.Stderr, "ansforge %s — %s\n\nUsage:\n  ansforge %s [path] [flags]\n\nFlags:\n", name, what, name)
		fs.PrintDefaults()
	}
}
