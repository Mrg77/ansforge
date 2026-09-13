package report

import "testing"

func TestHTMLRenders(t *testing.T) {
	r := &Report{Tool: "ansforge", Subject: "ansible", Scanned: "12 files",
		Findings: []Finding{
			{Severity: High, Category: "security", Rule: "plaintext-secret", File: "vars.yml", Line: 3,
				Message: "A credential is hard-coded.", Fix: "Use Vault."},
			{Severity: Low, Category: "style", Rule: "become-everywhere", File: "site.yml", Line: 4,
				Message: "Play-level escalation.", Fix: "Scope it."},
		}}
	h := r.HTML()
	for _, want := range []string{"<!doctype html>", "plaintext-secret", "vars.yml:3", "ansforge", "prefers-color-scheme"} {
		if !contains(h, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	if contains(h, "<script") {
		t.Fatal("the report must contain no JavaScript")
	}
}

func contains(h, s string) bool {
	for i := 0; i+len(s) <= len(h); i++ {
		if h[i:i+len(s)] == s {
			return true
		}
	}
	return false
}
