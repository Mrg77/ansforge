package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// recapRe extracts the PLAY RECAP counters Ansible prints at the end of a run.
var recapRe = regexp.MustCompile(`ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)`)

// PlaybookCheckTool runs a playbook in check mode (--check --diff): Ansible
// reports what it WOULD change without touching anything. Mutating in name
// only — it is the safe rehearsal, so the policy treats it far more leniently
// than a real run.
type PlaybookCheckTool struct{}

func (PlaybookCheckTool) Name() string   { return "playbook_check" }
func (PlaybookCheckTool) Danger() Danger { return Mutating }
func (PlaybookCheckTool) Description() string {
	return "Dry-run a playbook (--check --diff): shows what would change without changing " +
		"anything. Always prefer this over a real run when the goal is to verify."
}
func (PlaybookCheckTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"playbook":  map[string]any{"type": "string", "description": "Playbook path."},
			"inventory": map[string]any{"type": "string", "description": "Inventory path or host list (e.g. 'localhost,')."},
			"limit":     map[string]any{"type": "string", "description": "Optional host pattern to restrict the run."},
		},
		"required":             []string{"playbook", "inventory"},
		"additionalProperties": false,
	}
}

func (PlaybookCheckTool) Run(ctx context.Context, input json.RawMessage) (string, error) {
	return runPlaybook(ctx, input, true)
}

// PlaybookRunTool executes a playbook for real against an inventory. This is
// THE destructive action in Ansible: there is no `destroy` verb, which is
// exactly why it needs an explicit gate — `ansible-playbook` reads as harmless
// and changes production.
type PlaybookRunTool struct{}

func (PlaybookRunTool) Name() string   { return "playbook_run" }
func (PlaybookRunTool) Danger() Danger { return Destructive }
func (PlaybookRunTool) Description() string {
	return "Run a playbook FOR REAL against an inventory — this changes remote machines. " +
		"Passes through the safety policy. Use playbook_check first unless explicitly asked to apply."
}
func (PlaybookRunTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"playbook":  map[string]any{"type": "string", "description": "Playbook path."},
			"inventory": map[string]any{"type": "string", "description": "Inventory path or host list."},
			"limit":     map[string]any{"type": "string", "description": "Optional host pattern to restrict the run."},
		},
		"required":             []string{"playbook", "inventory"},
		"additionalProperties": false,
	}
}

func (PlaybookRunTool) Run(ctx context.Context, input json.RawMessage) (string, error) {
	return runPlaybook(ctx, input, false)
}

func runPlaybook(ctx context.Context, input json.RawMessage, check bool) (string, error) {
	var in struct {
		Playbook  string `json:"playbook"`
		Inventory string `json:"inventory"`
		Limit     string `json:"limit"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	if !have("ansible-playbook") {
		return "", fmt.Errorf("ansible-playbook is not installed")
	}
	pb, err := confine(in.Playbook)
	if err != nil {
		return "", err
	}
	args := []string{"-i", in.Inventory, pb}
	if check {
		args = append(args, "--check", "--diff")
	}
	if in.Limit != "" {
		args = append(args, "--limit", in.Limit)
	}
	out, err := run(ctx, projectRoot, 30*time.Minute, "ansible-playbook", args...)
	mode := "real run"
	if check {
		mode = "check mode (nothing changed)"
	}
	if err != nil {
		return "", fmt.Errorf("playbook failed (%s):\n%s", mode, truncate(out, 8000))
	}
	return fmt.Sprintf("playbook completed — %s.\n%s", mode, truncate(out, 6000)), nil
}

// ---------------------------------------------------------------------------
// idempotence_check
// ---------------------------------------------------------------------------

// IdempotenceTool plays a playbook twice and requires the second pass to report
// changed=0.
//
// Idempotence is Ansible's founding promise and the least verified one. It
// matters most where a convergence mechanism replays a playbook on a schedule:
// a task that reports `changed` on every pass drowns the real drift, and people
// stop reading the reports — which is when an actual change slips through.
type IdempotenceTool struct{}

func (IdempotenceTool) Name() string   { return "idempotence_check" }
func (IdempotenceTool) Danger() Danger { return Destructive }
func (IdempotenceTool) Description() string {
	return "Run a playbook twice and verify the second pass reports changed=0. A task still " +
		"reporting changed on the second pass is not idempotent — usually a command without " +
		"creates/changed_when, or content that embeds a timestamp. Runs for real, so it is gated."
}
func (IdempotenceTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"playbook":  map[string]any{"type": "string", "description": "Playbook path."},
			"inventory": map[string]any{"type": "string", "description": "Inventory path or host list (e.g. 'localhost,')."},
		},
		"required":             []string{"playbook", "inventory"},
		"additionalProperties": false,
	}
}

func (IdempotenceTool) Run(ctx context.Context, input json.RawMessage) (string, error) {
	var in struct {
		Playbook  string `json:"playbook"`
		Inventory string `json:"inventory"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	if !have("ansible-playbook") {
		return "", fmt.Errorf("ansible-playbook is not installed")
	}
	pb, err := confine(in.Playbook)
	if err != nil {
		return "", err
	}
	args := []string{"-i", in.Inventory, pb}

	if _, err := run(ctx, projectRoot, 30*time.Minute, "ansible-playbook", args...); err != nil {
		return "", fmt.Errorf("first pass failed — fix that before testing idempotence")
	}
	second, err := run(ctx, projectRoot, 30*time.Minute, "ansible-playbook", args...)
	if err != nil {
		return "", fmt.Errorf("second pass failed:\n%s", truncate(second, 4000))
	}

	changed := totalChanged(second)
	if changed == 0 {
		return "idempotent: the second pass reported changed=0 on every host.", nil
	}
	return fmt.Sprintf("NOT idempotent: the second pass still reports changed=%d.\n\n"+
		"Look for: `command`/`shell` without `creates` or `changed_when`, a template whose content "+
		"embeds a timestamp, or a file mode that is reset each run.\n\n%s",
		changed, truncate(second, 5000)), nil
}

// totalChanged sums the changed= counter across every host in a PLAY RECAP.
func totalChanged(out string) int {
	total := 0
	for _, m := range recapRe.FindAllStringSubmatch(out, -1) {
		n, _ := strconv.Atoi(m[2])
		total += n
	}
	return total
}

// hostsFrom is a small helper kept for readability in reports.
func hostsFrom(out string) []string {
	var hosts []string
	for _, line := range strings.Split(out, "\n") {
		if recapRe.MatchString(line) {
			hosts = append(hosts, strings.Fields(line)[0])
		}
	}
	return hosts
}
