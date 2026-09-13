package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Mrg77/ansforge/internal/anthropic"
	"github.com/Mrg77/ansforge/internal/report"
	"github.com/Mrg77/ansforge/internal/trace"
)

// maxSnippet bounds how much of a file is sent per finding. A finding needs its
// surroundings, not the whole role — and tokens are billed.
const maxSnippet = 40

// secretish redacts anything that looks like a credential before a line leaves
// the machine. --explain sends real code to an API, so this is not optional: a
// tool that leaks a password while explaining why you should not hard-code one
// would be worse than useless.
var secretish = regexp.MustCompile(`(?i)((?:password|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*)["']?[^\s"'{}]{4,}`)

// explain adds the AI layer to a deterministic report: prose plus a real
// before/after taken from the actual code.
//
// One batched call for the whole report, not one per finding — a report with
// thirty findings would otherwise cost thirty round-trips for no added insight.
// The deterministic findings stand on their own; this only annotates them, and a
// failure here never invalidates them.
func explain(r *report.Report) error {
	if len(r.Findings) == 0 {
		return nil
	}
	client, err := anthropic.New()
	if err != nil {
		return err
	}

	groups := r.Groups()
	type item struct {
		ID      string `json:"id"`
		Rule    string `json:"rule"`
		Message string `json:"message"`
		File    string `json:"file"`
		Snippet string `json:"snippet"`
	}
	var items []item
	for _, g := range groups {
		f := g.Findings[0] // one explanation per problem, not per occurrence
		items = append(items, item{
			ID: f.ID(), Rule: f.Rule, Message: f.Message, File: f.File,
			Snippet: snippet(f.File, f.Line),
		})
	}
	payload, err := json.Marshal(items)
	if err != nil {
		return err
	}

	system := `You explain Ansible security findings to a DevOps engineer who will apply the fix by hand.

For each finding you are given the rule, the message, and the surrounding YAML (credentials
already redacted). Return ONLY a JSON array, one object per finding:

  {"id": "<the id you were given>",
   "prose": "<two sentences: what breaks in practice, and why the fix works>",
   "before": "<the exact lines from the snippet that are wrong>",
   "after":  "<those lines, corrected, copy-pasteable, same indentation>"}

Rules:
- before/after must be REAL YAML from the snippet you were given, not an invented example.
  Keep the indentation: the engineer pastes this back into the file.
- If the snippet does not actually contain the problem, return an empty before/after and say
  so in the prose. A wrong diff is worse than no diff.
- Use fully-qualified module names, no_log on credential tasks, checksums on get_url, and
  the | quote filter on shell interpolation.
- No preamble, no markdown fences, no commentary outside the JSON.`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	resp, err := client.CreateMessage(ctx, system, []anthropic.Message{{
		Role:    "user",
		Content: []anthropic.ContentBlock{{Type: "text", Text: string(payload)}},
	}}, nil)
	if err != nil {
		return err
	}

	var text strings.Builder
	for _, c := range resp.Content {
		if c.Type == "text" {
			text.WriteString(c.Text)
		}
	}

	var out []struct {
		ID     string `json:"id"`
		Prose  string `json:"prose"`
		Before string `json:"before"`
		After  string `json:"after"`
	}
	raw := strings.TrimSpace(text.String())
	if i := strings.Index(raw, "["); i > 0 {
		raw = raw[i:] // tolerate a stray preamble rather than losing the whole call
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return fmt.Errorf("could not parse the model's answer: %w", err)
	}

	r.Enriched = map[string]report.Enrichment{}
	for _, e := range out {
		r.Enriched[e.ID] = report.Enrichment{Prose: e.Prose, Before: e.Before, After: e.After}
	}

	in, outTok := resp.Usage.InputTokens, resp.Usage.OutputTokens
	r.Cost = report.Cost{
		Model: client.Model(), InputTokens: in, OutputTokens: outTok,
		USD: trace.EstimateCost(client.Model(), in, outTok),
	}
	return nil
}

// snippet returns the lines around a finding, with anything credential-shaped
// redacted before it can leave the machine.
func snippet(file string, line int) string {
	wd, _ := os.Getwd()
	b, err := os.ReadFile(filepath.Join(wd, file))
	if err != nil {
		return ""
	}
	lines := strings.Split(string(b), "\n")
	start, end := 0, len(lines)
	if line > 0 {
		start = max(0, line-1-maxSnippet/2)
		end = min(len(lines), start+maxSnippet)
	} else if end > maxSnippet {
		end = maxSnippet
	}
	var out []string
	for _, l := range lines[start:end] {
		out = append(out, secretish.ReplaceAllString(l, "${1}«redacted»"))
	}
	return strings.Join(out, "\n")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
