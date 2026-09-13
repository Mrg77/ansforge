package tools

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// ANSI colours, disabled when the output is not a terminal or when NO_COLOR is
// set (https://no-color.org). A report piped into a file or a CI log must stay
// readable as plain text.
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

// isTTY reports whether stdout is a terminal. Checked through the file mode so
// the package keeps no third-party dependency.
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// severityColor maps a severity to its colour and label.
func severityColor(sev string) (string, string) {
	switch sev {
	case "high":
		return cRed, "HIGH"
	case "medium":
		return cYellow, "MEDIUM"
	default:
		return cBlue, "LOW"
	}
}

// Render turns findings into a report a human reads top-to-bottom.
//
// The first version printed one block per finding, which meant the same
// paragraph sixteen times for sixteen occurrences of one problem. A report
// nobody reads to the end is a report that changes nothing, so identical
// findings are grouped: the explanation and the fix appear once, with every
// location listed under them.
func Render(tool string, findings []Finding) string {
	var b strings.Builder

	if len(findings) == 0 {
		fmt.Fprintf(&b, "%s%s✓%s %s: no findings.\n%s  Deterministic checks only — a clean report is not a proof of safety.%s\n",
			cGreen, cBold, cReset, tool, cDim, cReset)
		return b.String()
	}

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	// Header: the numbers first, so a glance is enough to know how bad it is.
	fmt.Fprintf(&b, "\n%s%s %s%s  %d finding(s)", cBold, cCyan, tool, cReset, len(findings))
	var parts []string
	for _, sev := range []string{"high", "medium", "low"} {
		if counts[sev] > 0 {
			col, label := severityColor(sev)
			parts = append(parts, fmt.Sprintf("%s%d %s%s", col, counts[sev], strings.ToLower(label), cReset))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(&b, "  ·  %s", strings.Join(parts, ", "))
	}
	b.WriteString("\n\n")

	// Group by (severity, rule, message): one explanation, many locations.
	type key struct{ sev, rule, msg, fix string }
	groups := map[key][]Finding{}
	var order []key
	for _, f := range findings {
		k := key{f.Severity, f.Rule, f.Message, f.Fix}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], f)
	}
	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(order, func(i, j int) bool {
		if rank[order[i].sev] != rank[order[j].sev] {
			return rank[order[i].sev] < rank[order[j].sev]
		}
		return order[i].rule < order[j].rule
	})

	for _, k := range order {
		g := groups[k]
		col, label := severityColor(k.sev)

		fmt.Fprintf(&b, "%s%s %s %s%s %s%s%s\n", col, cBold, label, cReset, col, k.rule, cReset, "")
		fmt.Fprintf(&b, "  %s\n", k.msg)

		// Locations, sorted and de-duplicated. A file:line is clickable in most
		// terminals and editors — that is what makes a finding actionable.
		seen := map[string]bool{}
		var locs []string
		for _, f := range g {
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			if f.Job != "" {
				loc += " (job " + f.Job + ")"
			}
			if f.Detail != "" {
				loc += "  " + f.Detail
			}
			if !seen[loc] {
				seen[loc] = true
				locs = append(locs, loc)
			}
		}
		sort.Strings(locs)
		for _, l := range locs {
			fmt.Fprintf(&b, "  %s→%s %s\n", cDim, cReset, l)
		}

		fmt.Fprintf(&b, "  %sfix:%s %s\n\n", cGreen, cReset, k.fix)
	}
	return b.String()
}
