package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scan runs the scanner over a temp project containing the given file.
func scan(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	SetProjectRoot(dir)
	in, _ := json.Marshal(map[string]string{"path": "."})
	out, err := SecurityScanTool{}.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	return out
}

func TestDetectsPlaintextSecret(t *testing.T) {
	out := scan(t, "vars.yml", "ansible_password: hunter2supersecret\n")
	if !strings.Contains(out, "plaintext-secret") {
		t.Fatalf("a hard-coded password must be reported, got:\n%s", out)
	}
	if !strings.Contains(out, "[HIGH]") {
		t.Fatal("a hard-coded credential is a high finding")
	}
}

// A vault reference or a Jinja lookup is the CORRECT pattern — reporting it
// would train people to ignore the scanner.
func TestIgnoresVaultAndLookup(t *testing.T) {
	for _, line := range []string{
		"ansible_password: \"{{ vault_db_password }}\"\n",
		"db_password: \"{{ lookup('env', 'DB_PASSWORD') }}\"\n",
		"api_token: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n",
		"tls_key_file: /etc/ssl/private/key.pem\n",
	} {
		if out := scan(t, "vars.yml", line); strings.Contains(out, "plaintext-secret") {
			t.Fatalf("correct pattern flagged as a plaintext secret: %q\n%s", line, out)
		}
	}
}

func TestDetectsValidateCertsOff(t *testing.T) {
	out := scan(t, "play.yml", "    ansible.builtin.uri:\n      validate_certs: no\n")
	if !strings.Contains(out, "validate-certs-off") {
		t.Fatalf("disabled TLS validation must be reported, got:\n%s", out)
	}
}

func TestDetectsDownloadWithoutChecksum(t *testing.T) {
	out := scan(t, "play.yml", "  - name: fetch\n    ansible.builtin.get_url:\n      url: https://example.com/bin.tgz\n")
	if !strings.Contains(out, "download-without-checksum") {
		t.Fatalf("get_url without a checksum must be reported, got:\n%s", out)
	}
}

func TestDetectsShellInterpolation(t *testing.T) {
	out := scan(t, "play.yml", "    ansible.builtin.shell: rm -rf {{ user_input }}\n")
	if !strings.Contains(out, "shell-interpolation") {
		t.Fatalf("unquoted interpolation into shell must be reported, got:\n%s", out)
	}
}

// The | quote filter is the fix; once applied the finding must disappear,
// otherwise fixing it changes nothing and people stop fixing.
func TestQuotedInterpolationIsAccepted(t *testing.T) {
	out := scan(t, "play.yml", "    ansible.builtin.shell: rm -rf {{ user_input | quote }}\n")
	if strings.Contains(out, "shell-interpolation") {
		t.Fatalf("a quoted variable must not be reported, got:\n%s", out)
	}
}

func TestCommentsAreIgnored(t *testing.T) {
	out := scan(t, "play.yml", "# ansible_password: hunter2supersecret\n")
	if strings.Contains(out, "plaintext-secret") {
		t.Fatalf("a commented line must not be reported, got:\n%s", out)
	}
}

func TestCleanProjectHasNoFindings(t *testing.T) {
	out := scan(t, "play.yml", "- name: ok\n  hosts: all\n  tasks:\n    - name: touch\n      ansible.builtin.file:\n        path: /tmp/x\n        state: touch\n        mode: \"0644\"\n")
	if !strings.Contains(out, "no findings") {
		t.Fatalf("a clean playbook should produce no findings, got:\n%s", out)
	}
}

// Path confinement is a security control of its own: a model must not be able
// to make the agent read or write outside the project.
func TestConfineRejectsTraversal(t *testing.T) {
	SetProjectRoot(t.TempDir())
	if _, err := confine("../../etc/passwd"); err == nil {
		t.Fatal("a path escaping the project root must be rejected")
	}
	if _, err := confine("roles/nginx/tasks/main.yml"); err != nil {
		t.Fatalf("a path inside the project must be accepted: %v", err)
	}
}
