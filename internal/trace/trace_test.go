package trace

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mrg77/ansforge/internal/tools"
)

func TestCostCalculation(t *testing.T) {
	tr, err := New("claude-sonnet-4-5", "")
	if err != nil {
		t.Fatal(err)
	}
	// 1,000,000 input @ $3/M + 1,000,000 output @ $15/M = $18.
	tr.Turn(1_000_000, 1_000_000)
	if got := tr.Cost(); got != 18.0 {
		t.Errorf("cost = %v, want 18.0", got)
	}
}

func TestUnknownModelStillCosts(t *testing.T) {
	tr, _ := New("some-future-model", "")
	tr.Turn(1_000_000, 0)
	if tr.Cost() == 0 {
		t.Error("unknown model should fall back to a non-zero default price")
	}
}

func TestAuditLogIsJSONL(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "sub", "audit.jsonl") // dir doesn't exist yet
	tr, err := New("claude-sonnet-4-5", logPath)
	if err != nil {
		t.Fatal(err)
	}
	tr.Turn(100, 50)
	tr.ToolCall("terraform_destroy", tools.Destructive, "deny", "prod blocked")
	tr.Close()

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("audit log not created: %v", err)
	}
	defer f.Close()

	var lines []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("audit line is not valid JSON: %q", sc.Text())
		}
		lines = append(lines, m)
	}
	if len(lines) != 2 {
		t.Fatalf("want 2 audit lines, got %d", len(lines))
	}
	if lines[0]["kind"] != "turn" || lines[1]["kind"] != "tool" {
		t.Errorf("unexpected event kinds: %v, %v", lines[0]["kind"], lines[1]["kind"])
	}
	if lines[1]["decision"] != "deny" || lines[1]["tool"] != "terraform_destroy" {
		t.Errorf("tool event not recorded correctly: %v", lines[1])
	}
	// Every event must carry a timestamp.
	if lines[0]["time"] == "" {
		t.Error("event missing timestamp")
	}
}

func TestAuditOffWritesNoFile(t *testing.T) {
	tr, err := New("claude-sonnet-4-5", "") // empty path = no file
	if err != nil {
		t.Fatal(err)
	}
	tr.Turn(10, 10) // must not panic with a nil sink
	tr.ToolCall("terraform_plan", tools.ReadOnly, "allow", "")
	// Summary still works.
	if !strings.Contains(tr.Summary(), "run summary") {
		t.Error("summary should still render without a log file")
	}
}

func TestSummaryCountsGuardActions(t *testing.T) {
	tr, _ := New("claude-sonnet-4-5", "")
	tr.Turn(200, 100)
	tr.ToolCall("terraform_destroy", tools.Destructive, "deny", "prod")
	tr.ToolCall("terraform_apply", tools.Mutating, "confirm", "approved")
	tr.ToolCall("terraform_plan", tools.ReadOnly, "allow", "")
	s := tr.Summary()
	if !strings.Contains(s, "3 tool call(s)") || !strings.Contains(s, "1 denied") || !strings.Contains(s, "1 confirmed") {
		t.Errorf("summary counts wrong: %s", s)
	}
}
