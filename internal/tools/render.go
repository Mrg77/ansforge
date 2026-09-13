package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RenderTemplateTool renders a Jinja2 template THROUGH ANSIBLE, not through a
// bare Jinja2 engine.
//
// This distinction is the whole point of the tool. A template rendered by a
// Python script with hand-supplied variables will happily resolve things that do
// not exist in a real run — `ansible_managed` is the classic case: Ansible
// injects it only in the `template` module, so the same string inside a `copy`
// module's `content:` passes every static check and then fails on the machine.
// ansible-lint sees valid Jinja; the host sees an undefined variable.
//
// Rendering with `ansible localhost -m ansible.builtin.template` uses the real
// mechanism: real precedence, real magic variables, real filters and plugins.
type RenderTemplateTool struct{}

func (RenderTemplateTool) Name() string   { return "render_template" }
func (RenderTemplateTool) Danger() Danger { return ReadOnly }
func (RenderTemplateTool) Description() string {
	return "Render a Jinja2 template THROUGH Ansible itself (not a Python Jinja2 script) and " +
		"return the result. This is the only way to catch an undefined variable that a hand-rolled " +
		"test would mask, because Ansible's magic variables (ansible_managed, inventory_hostname, " +
		"ansible_facts) only exist in a real render. Pass var_files for group_vars/defaults."
}
func (RenderTemplateTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"template":  map[string]any{"type": "string", "description": "Path to the .j2 template."},
			"var_files": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "YAML files to load as variables (group_vars, role defaults). Order matters: later wins."},
			"extra_vars": map[string]any{
				"type":        "object",
				"description": "Additional variables as a JSON object, applied last.",
			},
		},
		"required":             []string{"template"},
		"additionalProperties": false,
	}
}

func (RenderTemplateTool) Run(ctx context.Context, input json.RawMessage) (string, error) {
	var in struct {
		Template  string         `json:"template"`
		VarFiles  []string       `json:"var_files"`
		ExtraVars map[string]any `json:"extra_vars"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	if !have("ansible") {
		return "", fmt.Errorf("ansible is not installed — install it to render templates the real way")
	}
	tpl, err := confine(in.Template)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(tpl); err != nil {
		return "", fmt.Errorf("template not found: %s", in.Template)
	}

	out, err := os.CreateTemp("", "ansforge-render-*")
	if err != nil {
		return "", err
	}
	dest := out.Name()
	out.Close()
	defer os.Remove(dest)

	args := []string{"localhost", "-c", "local", "-m", "ansible.builtin.template",
		"-a", fmt.Sprintf("src=%s dest=%s", tpl, dest)}
	for _, vf := range in.VarFiles {
		p, err := confine(vf)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(p); err != nil {
			continue // a missing optional var file is not fatal; the render will say what is undefined
		}
		args = append(args, "-e", "@"+p)
	}
	if len(in.ExtraVars) > 0 {
		b, _ := json.Marshal(in.ExtraVars)
		args = append(args, "-e", string(b))
	}

	// ANSIBLE_LOCALHOST_WARNING silences the implicit-localhost notice that would
	// otherwise dominate the output and cost tokens for nothing.
	os.Setenv("ANSIBLE_LOCALHOST_WARNING", "false")
	os.Setenv("ANSIBLE_INVENTORY_UNPARSED_WARNING", "false")

	cmdOut, err := run(ctx, projectRoot, 2*time.Minute, "ansible", args...)
	if err != nil {
		msg := cmdOut
		if strings.Contains(cmdOut, "undefined") {
			msg += "\n\nAn undefined variable at render time is exactly the class of bug a " +
				"hand-written Jinja2 test hides. Either the variable is missing from var_files, " +
				"or it is a magic variable only available in another module (ansible_managed " +
				"exists in `template`, not in `copy`'s content:)."
		}
		return "", fmt.Errorf("render failed:\n%s", truncate(msg, 6000))
	}

	body, err := os.ReadFile(dest)
	if err != nil {
		return "", fmt.Errorf("rendered file unreadable: %w", err)
	}
	return fmt.Sprintf("rendered %s (%d bytes):\n\n%s", in.Template, len(body), truncate(string(body), 12000)), nil
}

// ---------------------------------------------------------------------------
// validate_rendered
// ---------------------------------------------------------------------------

// validator maps a config kind to the command that judges it, run inside a
// container so the check uses the same binary version production will.
type validator struct {
	image string
	args  func(mount string) []string
	hint  string
}

// validators is the registry of "who actually reads this file". Validating with
// the upstream tool — in the pinned image — is the difference between "the YAML
// parses" and "the daemon will accept it".
var validators = map[string]validator{
	"nginx": {
		image: "nginx:alpine",
		args: func(m string) []string {
			return []string{"-v", m + ":/etc/nginx/nginx.conf:ro", "nginx:alpine", "nginx", "-t"}
		},
		hint: "nginx -t inside the image that will serve it",
	},
	"prometheus": {
		image: "prom/prometheus:latest",
		args: func(m string) []string {
			return []string{"-v", m + ":/tmp/candidate.yml:ro", "--entrypoint", "promtool", "prom/prometheus:latest", "check", "config", "/tmp/candidate.yml"}
		},
		hint: "promtool check config",
	},
	"alertmanager": {
		image: "prom/alertmanager:latest",
		args: func(m string) []string {
			return []string{"-v", m + ":/tmp/candidate.yml:ro", "--entrypoint", "amtool", "prom/alertmanager:latest", "check-config", "/tmp/candidate.yml"}
		},
		hint: "amtool check-config",
	},
	"logrotate": {
		image: "alpine:latest",
		args: func(m string) []string {
			return []string{"-v", m + ":/etc/logrotate.d/candidate:ro", "alpine:latest", "sh", "-c",
				"apk add --no-cache logrotate >/dev/null 2>&1 && logrotate -d /etc/logrotate.d/candidate"}
		},
		hint: "logrotate -d (debug parse)",
	},
}

// ValidateRenderedTool feeds a rendered config to the binary that will consume
// it. A config can be perfectly valid YAML and still be refused by the daemon.
type ValidateRenderedTool struct{}

func (ValidateRenderedTool) Name() string   { return "validate_rendered" }
func (ValidateRenderedTool) Danger() Danger { return ReadOnly }
func (ValidateRenderedTool) Description() string {
	return "Validate a rendered config file with the upstream tool that consumes it, inside a " +
		"container (nginx -t, promtool, amtool, logrotate -d). Valid YAML is not the same as a " +
		"config the daemon accepts. Requires Docker; reports plainly when it is absent."
}
func (ValidateRenderedTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "Path to the rendered config file."},
			"kind": map[string]any{"type": "string", "description": "One of: nginx, prometheus, alertmanager, logrotate."},
		},
		"required":             []string{"path", "kind"},
		"additionalProperties": false,
	}
}

func (ValidateRenderedTool) Run(ctx context.Context, input json.RawMessage) (string, error) {
	var in struct {
		Path string `json:"path"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	v, ok := validators[strings.ToLower(in.Kind)]
	if !ok {
		kinds := make([]string, 0, len(validators))
		for k := range validators {
			kinds = append(kinds, k)
		}
		return "", fmt.Errorf("unknown kind %q — supported: %s", in.Kind, strings.Join(kinds, ", "))
	}
	if !have("docker") {
		return fmt.Sprintf("docker is not available — cannot run %s. The file was not validated; "+
			"say so rather than implying it passed.", v.hint), nil
	}
	p, err := confine(in.Path)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	args := append([]string{"run", "--rm"}, v.args(abs)...)
	out, err := run(ctx, projectRoot, 5*time.Minute, "docker", args...)
	if err != nil {
		return "", fmt.Errorf("%s rejected the config:\n%s", v.hint, truncate(out, 5000))
	}
	return fmt.Sprintf("%s accepted the config.\n%s", v.hint, truncate(out, 2000)), nil
}
