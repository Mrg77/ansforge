// Package report is the shared deliverable layer of the *forge agents.
//
// The three tools (tfforge, ansforge, ciforge) look at different things and must
// behave the same way, because an engineer who learns one should already know the
// others: the same subcommands, the same flags, the same severities, the same
// exit-code rule. This package holds what that sameness is made of — the finding
// model, the ordering, the text and JSON and HTML renderers, and the gate.
//
// The contract, identical across the family:
//
//	<tool> "<task>"      the agent          costs tokens
//	<tool> scan [path]   gate one scope     free, deterministic
//	<tool> audit [path]  report the tree    free, deterministic
//	<tool> fix [path]    fix and re-check   costs tokens
//	<tool> version
//
// Shared flags: --json, --html [--out FILE], --explain, --fail-on, --top.
//
// Why deterministic and agentic are separate commands rather than one smart
// entry point: a gate must return the same verdict on the same input, today and
// in a year. A model cannot promise that. So the free half decides, and the
// paid half advises.
package report

import (
	"fmt"
	"sort"
	"strings"
)

// Severity is the shared scale. Five levels, because Terraform findings
// genuinely span that range; a tool with three simply never emits the others.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// rank orders severities worst-first. Unknown values sort last rather than
// crashing — a finding with a typo in its severity must still be reported.
func rank(s Severity) int {
	switch Severity(strings.ToLower(string(s))) {
	case Critical:
		return 0
	case High:
		return 1
	case Medium:
		return 2
	case Low:
		return 3
	case Info:
		return 4
	}
	return 5
}

// AtLeast reports whether s is as bad as threshold, or worse. This is the single
// definition of "does this fail the build" for the whole family.
func AtLeast(s, threshold Severity) bool {
	if strings.EqualFold(string(threshold), "none") {
		return false
	}
	return rank(s) <= rank(threshold)
}

// Finding is one issue, with everything needed to act on it. The JSON tags are
// part of the contract: another tool aggregates the three outputs, so the keys
// must match across them.
type Finding struct {
	Severity Severity `json:"severity"`
	Category string   `json:"category,omitempty"` // security, best-practice, structure…
	Rule     string   `json:"rule,omitempty"`
	File     string   `json:"file"`
	Line     int      `json:"line,omitempty"`
	Scope    string   `json:"scope,omitempty"`  // job, role, module — whatever the domain calls it
	Detail   string   `json:"detail,omitempty"` // what exactly triggered it
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`
}

// Location renders "file:line (scope) detail" — clickable in a terminal, and the
// reason a finding is actionable rather than merely true.
func (f Finding) Location() string {
	loc := f.File
	if f.Line > 0 {
		loc = fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	if f.Scope != "" {
		loc += " (" + f.Scope + ")"
	}
	if f.Detail != "" {
		loc += "  " + f.Detail
	}
	return loc
}

// key groups findings that share an explanation, so one problem in sixteen
// places is one paragraph and sixteen locations — not sixteen paragraphs.
func (f Finding) key() string {
	return string(f.Severity) + "\x00" + f.Rule + "\x00" + f.Message
}

// Enrichment is the optional AI layer for one finding: prose, plus a real
// before/after taken from the actual code. Empty when --explain was not used.
type Enrichment struct {
	Prose  string `json:"prose,omitempty"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// Cost is the FinOps summary of the --explain call, printed in every renderer's
// footer. An agent whose spend you cannot see is an agent you cannot budget.
type Cost struct {
	Model        string  `json:"model,omitempty"`
	InputTokens  int     `json:"input_tokens,omitempty"`
	OutputTokens int     `json:"output_tokens,omitempty"`
	USD          float64 `json:"usd,omitempty"`
}

func (c Cost) Zero() bool { return c.InputTokens == 0 && c.OutputTokens == 0 }

// Report is what every subcommand produces and every renderer consumes.
type Report struct {
	Tool      string                `json:"tool"`    // ansforge, ciforge, tfforge
	Subject   string                `json:"subject"` // what was analysed: a path, a repo
	Scanned   string                `json:"scanned"` // human summary: "9 directories · 55 files"
	Findings  []Finding             `json:"findings"`
	Enriched  map[string]Enrichment `json:"enriched,omitempty"` // keyed by Finding.ID()
	Cost      Cost                  `json:"cost,omitempty"`
	Truncated bool                  `json:"truncated,omitempty"`
}

// ID identifies a finding across renderers and across the AI layer, so an
// enrichment written once can be looked up by any of them.
func (f Finding) ID() string {
	return fmt.Sprintf("%s|%d|%s", f.File, f.Line, f.Rule)
}

// Sort orders findings worst-first, then by file, so two runs on unchanged code
// produce byte-identical output. Reproducibility is not a detail: a report that
// reshuffles itself cannot be diffed between two commits.
func (r *Report) Sort() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) < rank(b.Severity)
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}

// Counts returns the number of findings per severity.
func (r *Report) Counts() map[Severity]int {
	out := map[Severity]int{}
	for _, f := range r.Findings {
		out[Severity(strings.ToLower(string(f.Severity)))]++
	}
	return out
}

// Worst returns the worst severity present, or "" when the report is clean.
func (r *Report) Worst() Severity {
	worst := Severity("")
	for _, f := range r.Findings {
		if worst == "" || rank(f.Severity) < rank(worst) {
			worst = Severity(strings.ToLower(string(f.Severity)))
		}
	}
	return worst
}

// ExitCode is the gate: 1 when anything reaches the threshold, else 0. Counting
// findings, never grepping rendered text — the report is coloured, and a gate
// must not depend on how something is displayed.
func (r *Report) ExitCode(failOn Severity) int {
	for _, f := range r.Findings {
		if AtLeast(f.Severity, failOn) {
			return 1
		}
	}
	return 0
}

// Group bundles findings that share an explanation.
type Group struct {
	Severity Severity
	Rule     string
	Message  string
	Fix      string
	Findings []Finding
}

// Groups returns the findings grouped by problem, worst-first.
func (r *Report) Groups() []Group {
	r.Sort()
	var order []string
	byKey := map[string]*Group{}
	for _, f := range r.Findings {
		k := f.key()
		g, ok := byKey[k]
		if !ok {
			g = &Group{Severity: f.Severity, Rule: f.Rule, Message: f.Message, Fix: f.Fix}
			byKey[k] = g
			order = append(order, k)
		}
		g.Findings = append(g.Findings, f)
	}
	out := make([]Group, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}
