package main

import (
	"context"
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
	_ = fs.Parse(args)

	path := "."
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	wd, _ := os.Getwd()
	tools.SetProjectRoot(wd)

	in, _ := json.Marshal(map[string]string{"path": path})
	out, err := tools.SecurityScanTool{}.Run(context.Background(), in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ansforge scan:", err)
		return 2
	}

	if *asJSON {
		fmt.Println(string(mustJSON(out)))
	} else {
		fmt.Println(out)
	}

	switch strings.ToLower(*failOn) {
	case "none":
		return 0
	case "low":
		if strings.Contains(out, "[LOW]") || strings.Contains(out, "[MEDIUM]") || strings.Contains(out, "[HIGH]") {
			return 1
		}
	case "medium":
		if strings.Contains(out, "[MEDIUM]") || strings.Contains(out, "[HIGH]") {
			return 1
		}
	default: // high
		if strings.Contains(out, "[HIGH]") {
			return 1
		}
	}
	return 0
}

// mustJSON wraps the human report so `--json` stays machine-readable without a
// second scanning pass.
func mustJSON(report string) []byte {
	b, _ := json.MarshalIndent(map[string]string{"report": report}, "", "  ")
	return b
}
