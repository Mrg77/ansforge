package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Finding is one security issue with enough context to act on it.
type Finding struct {
	Severity string // high | medium | low
	File     string
	Line     int
	Rule     string
	Message  string
	Fix      string
}

// rule is a heuristic: a pattern, and what it means when it matches.
type rule struct {
	id       string
	severity string
	re       *regexp.Regexp
	message  string
	fix      string
	// skip lets a rule ignore a line that is obviously fine (a lookup, a
	// variable reference) to keep the false-positive rate low. Noise is what
	// makes a scanner ignored.
	skip *regexp.Regexp
}

var rules = []rule{
	{
		id:       "plaintext-secret",
		severity: "high",
		re:       regexp.MustCompile(`(?i)^\s*(ansible_password|ansible_become_password|ansible_ssh_pass|.*_password|.*_secret|.*_token|.*_api_key)\s*:\s*["']?[^{\s"']{6,}`),
		skip:     regexp.MustCompile(`(?i)\{\{|lookup\(|vault|!vault|_file\s*:|_path\s*:|CHANGEME|example|xxx`),
		message:  "A credential appears to be hard-coded in plain text.",
		fix:      "Move it to Ansible Vault (ansible-vault encrypt_string) or an external secret store, and reference it with a lookup.",
	},
	{
		id:       "no-log-missing",
		severity: "medium",
		re:       regexp.MustCompile(`(?i)(password|secret|token|api_key)\s*[:=]`),
		skip:     regexp.MustCompile(`(?i)no_log|_file\s*:|_path\s*:|^\s*#`),
		message:  "A task handling a credential may echo it into the log.",
		fix:      "Add `no_log: true` to that task. Ansible logs module arguments by default, including secrets.",
	},
	{
		id:       "validate-certs-off",
		severity: "high",
		re:       regexp.MustCompile(`(?i)validate_certs\s*:\s*(no|false)`),
		message:  "TLS certificate validation is disabled — the connection is open to interception.",
		fix:      "Remove validate_certs, or point ca_path at the internal CA bundle if the certificate is private.",
	},
	{
		id:       "download-without-checksum",
		severity: "high",
		re:       regexp.MustCompile(`(?i)^\s*(ansible\.builtin\.)?get_url\s*:`),
		message:  "A file is downloaded without a pinned checksum (checked at the task level).",
		fix:      "Add `checksum: sha256:...` and bump it together with the version. Without it, a compromised upstream release becomes arbitrary code on your hosts.",
	},
	{
		id:       "shell-interpolation",
		severity: "high",
		re:       regexp.MustCompile(`(?i)^\s*(ansible\.builtin\.)?(shell|command)\s*:.*\{\{`),
		skip:     regexp.MustCompile(`\|\s*quote\s*\}\}`),
		message:  "A variable is interpolated into a shell command without quoting — command injection if the value is attacker-controlled.",
		fix:      "Apply the `| quote` filter, or use a dedicated module instead of shell.",
	},
	{
		id:       "become-everywhere",
		severity: "low",
		re:       regexp.MustCompile(`(?i)^\s*become\s*:\s*(yes|true)\s*$`),
		message:  "Privilege escalation is enabled at play level — every task runs as root, including those that do not need it.",
		fix:      "Move `become: true` onto the tasks that require it.",
	},
	{
		id:       "world-writable-mode",
		severity: "medium",
		// Only the LAST digit matters here: it is the "other" class. 0755 on a
		// directory is correct and must not be reported — a scanner that cries
		// wolf on correct code teaches people to ignore it.
		re:      regexp.MustCompile(`(?i)^\s*mode\s*:\s*["']?0?[0-7][0-7][2367]\b`),
		message: "A file or directory is world-writable (the last digit grants write to \"other\").",
		fix:     "Drop the write bit for others: 0644 for a config file, 0755 for a directory, 0600 for anything holding a credential.",
	},
	{
		id:       "host-key-checking-off",
		severity: "medium",
		re:       regexp.MustCompile(`(?i)host_key_checking\s*[:=]\s*(no|false)`),
		message:  "SSH host key checking is disabled — the first connection to a spoofed host would succeed silently.",
		fix:      "Keep host key checking on and pre-populate known_hosts, or use a connection plugin that does not rely on SSH.",
	},
}

// SecurityScanTool walks a project and reports Ansible-specific weaknesses.
//
// These heuristics complement ansible-lint, they do not replace it: a solid net,
// not an absolute barrier. Each finding carries the fix, because a finding
// without a remedy is noise.
type SecurityScanTool struct{}

func (SecurityScanTool) Name() string   { return "security_scan" }
func (SecurityScanTool) Danger() Danger { return ReadOnly }
func (SecurityScanTool) Description() string {
	return "Scan Ansible content for security issues: plain-text credentials, missing no_log, " +
		"validate_certs disabled, downloads without a pinned checksum, shell interpolation, " +
		"over-broad become, world-writable modes. Complements ansible-lint rather than replacing it."
}
func (SecurityScanTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "Directory or file to scan (default: the project root)."},
		},
		"additionalProperties": false,
	}
}

func (SecurityScanTool) Run(_ context.Context, input json.RawMessage) (string, error) {
	var in struct {
		Path string `json:"path"`
	}
	_ = json.Unmarshal(input, &in)
	if in.Path == "" {
		in.Path = "."
	}
	root, err := confine(in.Path)
	if err != nil {
		return "", err
	}

	var findings []Finding
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "collections", ".cache", "node_modules", ".venv":
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yml" && ext != ".yaml" && ext != ".cfg" {
			return nil
		}
		findings = append(findings, scanFile(p, root)...)
		return nil
	})
	if err != nil {
		return "", err
	}

	if len(findings) == 0 {
		return "security_scan: no findings. (Heuristics complement ansible-lint; a clean scan is not a proof of safety.)", nil
	}

	order := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(findings, func(i, j int) bool {
		if order[findings[i].Severity] != order[findings[j].Severity] {
			return order[findings[i].Severity] < order[findings[j].Severity]
		}
		return findings[i].File < findings[j].File
	})

	var b strings.Builder
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(&b, "security_scan: %d finding(s) — %d high, %d medium, %d low\n\n",
		len(findings), counts["high"], counts["medium"], counts["low"])
	for _, f := range findings {
		fmt.Fprintf(&b, "[%s] %s:%d  (%s)\n  %s\n  fix: %s\n\n",
			strings.ToUpper(f.Severity), f.File, f.Line, f.Rule, f.Message, f.Fix)
	}
	return truncate(b.String(), 12000), nil
}

func scanFile(path, root string) []Finding {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	rel, _ := filepath.Rel(root, path)
	var out []Finding
	for i, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, r := range rules {
			if !r.re.MatchString(line) {
				continue
			}
			if r.skip != nil && r.skip.MatchString(line) {
				continue
			}
			out = append(out, Finding{
				Severity: r.severity, File: rel, Line: i + 1,
				Rule: r.id, Message: r.message, Fix: r.fix,
			})
		}
	}
	return out
}
