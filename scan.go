package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Mrg77/ansforge/internal/tools"
)

// runScan is the CI subcommand: a deterministic security scan with no LLM and
// no API key. It exists because a pipeline gate must be reproducible — the same
// content must always produce the same verdict. The agent advises; this decides.
func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	failOn := fs.String("fail-on", "high", "Exit non-zero when a finding at this severity or above is present: high, medium, low, none.")
	asJSON := fs.Bool("json", false, "Emit findings as JSON.")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `ansforge scan — deterministic Ansible security scan (no LLM, no API key).

Usage:
  ansforge scan [path] [flags]

Flags:`)
		fs.PrintDefaults()
	}
	// Go's flag package stops at the first positional argument, so
	// `scan . --json` would silently ignore the flag. Reorder so both spellings
	// work: a CLI that quietly does the wrong thing is worse than one that errors.
	var positional, flags []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		} else {
			positional = append(positional, a)
		}
	}
	_ = fs.Parse(append(flags, positional...))

	path := "."
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	wd, _ := os.Getwd()
	tools.SetProjectRoot(wd)

	findings, err := tools.Scan(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ansforge scan:", err)
		return 2
	}

	if *asJSON {
		out, _ := json.MarshalIndent(map[string]any{
			"tool":         "ansforge",
			"findings":     findings,
			"count":        len(findings),
			"max_severity": tools.MaxSeverity(findings),
		}, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Print(tools.Render("security_scan", findings))
	}

	// Decide on counts, never by grepping rendered text: the report is coloured,
	// and a gate must not depend on how something is displayed.
	rank := map[string]int{"low": 1, "medium": 2, "high": 3}
	if strings.EqualFold(*failOn, "none") {
		return 0
	}
	threshold := rank[strings.ToLower(*failOn)]
	if threshold == 0 {
		threshold = rank["high"]
	}
	for _, f := range findings {
		if rank[f.Severity] >= threshold {
			return 1
		}
	}
	return 0
}
