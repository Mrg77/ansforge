package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// projectRoot confines every filesystem and command action to one directory.
// SetProjectRoot is called once from main; an empty root means "current
// directory". Nothing in this package may read or write outside it.
var projectRoot string

// SetProjectRoot fixes the directory the agent may operate in.
func SetProjectRoot(dir string) {
	abs, err := filepath.Abs(dir)
	if err == nil {
		projectRoot = filepath.Clean(abs)
	}
}

// confine resolves a user/model-supplied path against the project root and
// refuses anything that escapes it. Every tool that touches the filesystem or
// runs a command goes through this — a model that asks for "../../etc" gets an
// error, not a traversal.
func confine(p string) (string, error) {
	root := projectRoot
	if root == "" {
		root, _ = filepath.Abs(".")
	}
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, p)
	}
	abs = filepath.Clean(abs)
	rootClean := filepath.Clean(root)
	if abs != rootClean && !strings.HasPrefix(abs, rootClean+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside the allowed project root %q — ansforge won't operate there", p, rootClean)
	}
	return abs, nil
}

// run executes a command in dir with a timeout, returning combined output. The
// timeout stops a hung playbook or a container pull from blocking the loop
// forever.
func run(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(c, name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if c.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return string(out), err
}

// have reports whether a binary is on PATH. Tools degrade gracefully rather
// than failing the whole run when an optional linter is absent.
func have(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// truncate keeps tool output within a sane token budget. Findings matter more
// than the tail of a 5000-line log.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("\n… (%d more bytes truncated)", len(s)-max)
}

// ---------------------------------------------------------------------------
// ansible_lint
// ---------------------------------------------------------------------------

// LintTool runs ansible-lint, the community linter. Read-only: it never changes
// a file, so the guard lets it through unconditionally.
type LintTool struct{}

func (LintTool) Name() string   { return "ansible_lint" }
func (LintTool) Danger() Danger { return ReadOnly }
func (LintTool) Description() string {
	return "Run ansible-lint on a path (playbook, role, or directory). Reports style and " +
		"correctness issues. Note: ansible-lint validates FORM, not behaviour — a clean run does " +
		"not mean the playbook does the right thing on a machine."
}
func (LintTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path":    map[string]any{"type": "string", "description": "File or directory to lint (relative to the project)."},
			"profile": map[string]any{"type": "string", "description": "ansible-lint profile: min, basic, moderate, safety, shared, production. Default: production."},
		},
		"required":             []string{"path"},
		"additionalProperties": false,
	}
}

func (LintTool) Run(ctx context.Context, input json.RawMessage) (string, error) {
	var in struct {
		Path    string `json:"path"`
		Profile string `json:"profile"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	if !have("ansible-lint") {
		return "ansible-lint is not installed — skipping. Install it with `pip install ansible-lint` for form checks.", nil
	}
	target, err := confine(in.Path)
	if err != nil {
		return "", err
	}
	profile := in.Profile
	if profile == "" {
		profile = "production"
	}
	out, err := run(ctx, projectRoot, 5*time.Minute, "ansible-lint", "--profile", profile, target)
	if err != nil {
		return truncate(out, 8000), nil // findings are the signal, not an execution failure
	}
	return "ansible-lint passed (profile " + profile + ").\n" + truncate(out, 2000), nil
}

// ---------------------------------------------------------------------------
// ansible_syntax
// ---------------------------------------------------------------------------

// SyntaxTool runs ansible-playbook --syntax-check: it parses the playbook and
// every role it includes, without connecting to any host.
type SyntaxTool struct{}

func (SyntaxTool) Name() string   { return "ansible_syntax" }
func (SyntaxTool) Danger() Danger { return ReadOnly }
func (SyntaxTool) Description() string {
	return "Parse a playbook and the roles it includes (ansible-playbook --syntax-check). " +
		"Catches malformed YAML, unknown modules and broken includes. Connects to nothing."
}
func (SyntaxTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"playbook": map[string]any{"type": "string", "description": "Playbook path (relative to the project)."},
		},
		"required":             []string{"playbook"},
		"additionalProperties": false,
	}
}

func (SyntaxTool) Run(ctx context.Context, input json.RawMessage) (string, error) {
	var in struct {
		Playbook string `json:"playbook"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	if !have("ansible-playbook") {
		return "", fmt.Errorf("ansible-playbook is not installed — install ansible to use this tool")
	}
	pb, err := confine(in.Playbook)
	if err != nil {
		return "", err
	}
	out, err := run(ctx, projectRoot, 2*time.Minute, "ansible-playbook", "--syntax-check", "-i", "localhost,", pb)
	if err != nil {
		return "", fmt.Errorf("syntax check failed:\n%s", truncate(out, 4000))
	}
	return "syntax OK: " + in.Playbook, nil
}
