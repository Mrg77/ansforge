package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Colours are disabled when stdout is not a terminal or NO_COLOR is set
// (https://no-color.org), so a CI log stays readable as plain text.
var (
	colorOn = isTTY() && os.Getenv("NO_COLOR") == ""

	cReset  = paint("\033[0m")
	cBold   = paint("\033[1m")
	cDim    = paint("\033[2m")
	cRed    = paint("\033[31m")
	cYellow = paint("\033[33m")
	cBlue   = paint("\033[34m")
	cGreen  = paint("\033[32m")
	cCyan   = paint("\033[36m")
)

func paint(code string) string {
	if colorOn {
		return code
	}
	return ""
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func sevColor(s Severity) string {
	switch Severity(strings.ToLower(string(s))) {
	case Critical, High:
		return cRed
	case Medium:
		return cYellow
	case Low:
		return cBlue
	default:
		return cDim
	}
}

// Text renders the report for a human reading top to bottom.
//
// Findings are grouped by problem: one explanation, every location under it.
// The first version of this printed a block per finding, which meant the same
// paragraph sixteen times for one problem in sixteen places — and a report
// nobody reads to the end changes nothing.
//
// top caps the number of groups shown (0 = all); the banner always states the
// real total, so a capped report never reads as a complete one.
func (r *Report) Text(top int) string {
	var b strings.Builder

	if len(r.Findings) == 0 {
		fmt.Fprintf(&b, "\n%s%s✓%s %s — no findings", cGreen, cBold, cReset, r.Tool)
		if r.Scanned != "" {
			fmt.Fprintf(&b, " %s(%s)%s", cDim, r.Scanned, cReset)
		}
		fmt.Fprintf(&b, "\n%s  Deterministic checks only — a clean report is not a proof of safety.%s\n\n", cDim, cReset)
		return b.String()
	}

	counts := r.Counts()
	fmt.Fprintf(&b, "\n%s%s%s%s  %d finding(s)", cBold, cCyan, r.Tool, cReset, len(r.Findings))
	var parts []string
	for _, s := range []Severity{Critical, High, Medium, Low, Info} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s%d %s%s", sevColor(s), counts[s], s, cReset))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(&b, "  ·  %s", strings.Join(parts, ", "))
	}
	if r.Scanned != "" {
		fmt.Fprintf(&b, "\n%s%s%s", cDim, r.Scanned, cReset)
	}
	b.WriteString("\n\n")

	groups := r.Groups()
	shown := groups
	if top > 0 && len(groups) > top {
		shown = groups[:top]
	}

	for _, g := range shown {
		col := sevColor(g.Severity)
		fmt.Fprintf(&b, "%s%s %s %s%s %s\n", col, cBold, strings.ToUpper(string(g.Severity)), cReset, col+g.Rule+cReset, "")
		fmt.Fprintf(&b, "  %s\n", g.Message)

		seen := map[string]bool{}
		var locs []string
		for _, f := range g.Findings {
			if l := f.Location(); !seen[l] {
				seen[l] = true
				locs = append(locs, l)
			}
		}
		sort.Strings(locs)
		for _, l := range locs {
			fmt.Fprintf(&b, "  %s→%s %s\n", cDim, cReset, l)
		}

		// The AI layer, when --explain ran: prose, then the real before/after.
		if len(r.Enriched) > 0 {
			if e, ok := r.Enriched[g.Findings[0].ID()]; ok {
				if e.Prose != "" {
					fmt.Fprintf(&b, "  %s%s%s\n", cDim, e.Prose, cReset)
				}
				if e.Before != "" || e.After != "" {
					b.WriteString(diffBlock(e.Before, e.After))
				}
			}
		}

		if g.Fix != "" {
			fmt.Fprintf(&b, "  %sfix:%s %s\n", cGreen, cReset, g.Fix)
		}
		b.WriteString("\n")
	}

	if len(shown) < len(groups) {
		fmt.Fprintf(&b, "%s  showing %d of %d problems — --top 0 for all, --json for every finding%s\n\n",
			cDim, len(shown), len(groups), cReset)
	}
	if !r.Cost.Zero() {
		fmt.Fprintf(&b, "%s  AI explanation: %d in / %d out tokens · $%.4f (%s)%s\n\n",
			cDim, r.Cost.InputTokens, r.Cost.OutputTokens, r.Cost.USD, r.Cost.Model, cReset)
	}
	return b.String()
}

// diffBlock renders a before/after as a unified-looking diff: red for what goes,
// green for what replaces it. Copy-pasteable, which is the point.
func diffBlock(before, after string) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimRight(before, "\n"), "\n") {
		if l != "" {
			fmt.Fprintf(&b, "  %s- %s%s\n", cRed, l, cReset)
		}
	}
	for _, l := range strings.Split(strings.TrimRight(after, "\n"), "\n") {
		if l != "" {
			fmt.Fprintf(&b, "  %s+ %s%s\n", cGreen, l, cReset)
		}
	}
	return b.String()
}

// JSON renders the report for machines: another tool aggregates the three, so
// the shape is part of the contract.
func (r *Report) JSON() string {
	r.Sort()
	type out struct {
		Tool        string                `json:"tool"`
		Subject     string                `json:"subject,omitempty"`
		Scanned     string                `json:"scanned,omitempty"`
		Count       int                   `json:"count"`
		MaxSeverity string                `json:"max_severity"`
		Findings    []Finding             `json:"findings"`
		Enriched    map[string]Enrichment `json:"enriched,omitempty"`
		Cost        *Cost                 `json:"cost,omitempty"`
	}
	o := out{
		Tool: r.Tool, Subject: r.Subject, Scanned: r.Scanned,
		Count: len(r.Findings), MaxSeverity: string(r.Worst()),
		Findings: r.Findings, Enriched: r.Enriched,
	}
	if o.MaxSeverity == "" {
		o.MaxSeverity = "none"
	}
	if !r.Cost.Zero() {
		c := r.Cost
		o.Cost = &c
	}
	if o.Findings == nil {
		o.Findings = []Finding{}
	}
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return `{"error":"could not encode report"}`
	}
	return string(b)
}
