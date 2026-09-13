package report

import (
	"encoding/json"
	"flag"
	"io"
	"strings"
	"testing"
)

func sample() *Report {
	return &Report{Tool: "t", Subject: "s", Findings: []Finding{
		{Severity: Low, Rule: "b", File: "b.yml", Line: 2, Message: "low one"},
		{Severity: Critical, Rule: "a", File: "a.yml", Line: 1, Message: "critical one"},
		{Severity: Medium, Rule: "c", File: "c.yml", Message: "medium one"},
		{Severity: High, Rule: "d", File: "d.yml", Message: "high one"},
	}}
}

// Ordering is worst-first and stable: two runs on unchanged code must produce
// byte-identical output, or the report cannot be diffed between two commits.
func TestSortIsWorstFirstAndStable(t *testing.T) {
	r := sample()
	r.Sort()
	want := []Severity{Critical, High, Medium, Low}
	for i, w := range want {
		if r.Findings[i].Severity != w {
			t.Fatalf("position %d: want %s, got %s", i, w, r.Findings[i].Severity)
		}
	}
	first := r.Text(0)
	r.Sort()
	if r.Text(0) != first {
		t.Fatal("a second render must be identical")
	}
}

func TestWorstAndCounts(t *testing.T) {
	r := sample()
	if got := r.Worst(); got != Critical {
		t.Fatalf("worst: want critical, got %q", got)
	}
	if n := r.Counts()[High]; n != 1 {
		t.Fatalf("counts[high]: want 1, got %d", n)
	}
	empty := &Report{Tool: "t"}
	if got := empty.Worst(); got != "" {
		t.Fatalf("an empty report has no worst severity, got %q", got)
	}
}

// The gate is the same rule for every tool in the family, and it counts
// findings — it never greps rendered text, which is coloured.
func TestExitCodeThresholds(t *testing.T) {
	r := sample()
	for _, c := range []struct {
		failOn Severity
		want   int
	}{
		{Critical, 1}, {High, 1}, {Medium, 1}, {Low, 1}, {"none", 0},
	} {
		if got := r.ExitCode(c.failOn); got != c.want {
			t.Fatalf("--fail-on %s: want exit %d, got %d", c.failOn, c.want, got)
		}
	}

	onlyLow := &Report{Findings: []Finding{{Severity: Low, File: "x"}}}
	if got := onlyLow.ExitCode(High); got != 0 {
		t.Fatalf("a low finding must not fail --fail-on high, got %d", got)
	}
	if got := onlyLow.ExitCode(Low); got != 1 {
		t.Fatalf("a low finding must fail --fail-on low, got %d", got)
	}
	clean := &Report{}
	if got := clean.ExitCode(Low); got != 0 {
		t.Fatalf("a clean report always exits 0, got %d", got)
	}
}

// One problem in many places is one explanation and many locations — not the
// same paragraph repeated until nobody reads it.
func TestGroupsShareOneExplanation(t *testing.T) {
	r := &Report{Findings: []Finding{
		{Severity: High, Rule: "pin", File: "a.yml", Line: 1, Message: "same", Fix: "do x"},
		{Severity: High, Rule: "pin", File: "b.yml", Line: 9, Message: "same", Fix: "do x"},
		{Severity: High, Rule: "pin", File: "c.yml", Line: 3, Message: "same", Fix: "do x"},
	}}
	g := r.Groups()
	if len(g) != 1 {
		t.Fatalf("three occurrences of one problem must group into 1, got %d", len(g))
	}
	if len(g[0].Findings) != 3 {
		t.Fatalf("the group must keep all 3 locations, got %d", len(g[0].Findings))
	}
	txt := r.Text(0)
	if strings.Count(txt, "same") != 1 {
		t.Fatalf("the explanation must appear once, got %d times", strings.Count(txt, "same"))
	}
	for _, f := range []string{"a.yml:1", "b.yml:9", "c.yml:3"} {
		if !strings.Contains(txt, f) {
			t.Fatalf("every location must be listed, missing %s", f)
		}
	}
}

// The JSON shape is a contract: another tool aggregates the three outputs, so
// the keys must not drift.
func TestJSONContract(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal([]byte(sample().JSON()), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, k := range []string{"tool", "count", "max_severity", "findings"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("the aggregate contract requires key %q", k)
		}
	}
	if m["max_severity"] != "critical" {
		t.Fatalf("max_severity: want critical, got %v", m["max_severity"])
	}
	clean := (&Report{Tool: "t"}).JSON()
	if !strings.Contains(clean, `"max_severity": "none"`) {
		t.Fatalf("a clean report must report max_severity none, got %s", clean)
	}
	if !strings.Contains(clean, `"findings": []`) {
		t.Fatal("findings must be an empty array, never null — consumers iterate it")
	}
}

// --top caps what is shown and says so. A truncated report that reads like a
// complete one is worse than no report.
func TestTopCapsAndSaysSo(t *testing.T) {
	r := sample()
	out := r.Text(2)
	if !strings.Contains(out, "showing 2 of 4") {
		t.Fatalf("a capped report must state the real total, got:\n%s", out)
	}
	if strings.Contains(r.Text(0), "showing") {
		t.Fatal("an uncapped report must not claim to be capped")
	}
}

func TestCleanReportIsExplicit(t *testing.T) {
	out := (&Report{Tool: "ansforge"}).Text(0)
	if !strings.Contains(out, "no findings") {
		t.Fatalf("a clean report must say so, got:\n%s", out)
	}
	if !strings.Contains(out, "not a proof of safety") {
		t.Fatal("a clean report must not be mistaken for a guarantee")
	}
}

// Flag order must not change meaning, and a flag's value must never be mistaken
// for a positional argument — `audit . --out r.html` used to analyse "r.html".
func TestParseArgsHandlesEitherOrder(t *testing.T) {
	cases := [][]string{
		{"ansible", "--json"},
		{"--json", "ansible"},
		{"ansible", "--out", "r.html", "--html"},
		{"--html", "--out", "r.html", "ansible"},
		{"ansible", "--out=r.html"},
	}
	for _, args := range cases {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var o Options
		o.Bind(fs, "high")
		rest := ParseArgs(fs, args)
		if len(rest) != 1 || rest[0] != "ansible" {
			t.Fatalf("%v: want positional [ansible], got %v", args, rest)
		}
		if o.Out != "" && o.Out != "r.html" {
			t.Fatalf("%v: --out picked up %q", args, o.Out)
		}
	}
}

// The CSS-only tabs are the one place a template can produce something that
// parses as HTML and still shows nothing. The selector list must be
// comma-separated and well-formed, or every panel stays hidden.
func TestHTMLTabSelectorIsWellFormed(t *testing.T) {
	r := &Report{Tool: "t", Subject: "s", Findings: []Finding{
		{Severity: High, Category: "security", Rule: "a", File: "a.yml", Message: "m"},
		{Severity: Low, Category: "style", Rule: "b", File: "b.yml", Message: "n"},
	}}
	h := r.HTML()
	// Three tabs (All, Security, Style) => three selectors, two separators.
	sel := h[strings.Index(h, "#t0:checked"):]
	sel = sel[:strings.Index(sel, "{display:block}")]
	if strings.Count(sel, "#t") != 3 {
		t.Fatalf("want one selector per tab, got %q", sel)
	}
	if strings.Count(sel, ",") != 2 {
		t.Fatalf("selectors must be comma-separated, got %q", sel)
	}
	if strings.Contains(sel, ",{") || strings.Contains(sel, "#p0#t") {
		t.Fatalf("malformed selector list: %q", sel)
	}
	// And the findings must actually be in the markup.
	for _, want := range []string{"a.yml", "b.yml", "security", "style"} {
		if !strings.Contains(strings.ToLower(h), want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
}
