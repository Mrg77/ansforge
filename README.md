# ansforge

*Read this in [French](README.fr.md).*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**An AI agent that builds, validates and secures Ansible — by running it, not by reading it.**

`ansible-lint` validates **form**. It cannot tell you that a template references a
variable which will not exist on the host, that a config is valid YAML and still
rejected by the daemon that consumes it, or that a playbook will report `changed`
forever because a task lacks `changed_when`.

ansforge closes that gap. It renders templates **through Ansible itself**, validates
the result with the **upstream tool inside a container**, and checks idempotence by
**playing twice**. Every action that touches a real machine passes through
**policy-as-code**, so the agent can help without being able to converge production
by accident.

Built **from scratch on the Anthropic Messages API** — no agent framework, so the
loop is fully visible.

> Not another "LLM that writes YAML". The value is the proof: an agent whose work
> you can verify, whose reach you can bound, and whose spend you can see.

## Why this exists

Three bugs from a real AWS platform, all of which passed `ansible-lint` on the
production profile:

1. **`{{ ansible_managed }}` inside a `copy` module's `content:`.** That variable is
   injected only by the `template` module. The lint saw valid Jinja. A Python test
   supplied the variable by hand and passed too. The instance failed at first boot.
2. **`stub_status` bound to `listen 127.0.0.1:8080` inside a container.** `nginx -t`
   said the config was fine. But that address is the *container's* loopback —
   unreachable from the host, where the Prometheus exporter runs. Monitoring would
   have gone silently blind.
3. **Log rotation vanished with the package it came from.** Containerising nginx
   removed the RPM, and with it `/etc/logrotate.d/nginx`. Nothing was syntactically
   wrong. The access log would have filled the root volume.

None was detectable without executing. That is the thesis of this tool.

## The family contract

`tfforge`, `ansforge` and `ciforge` look at different things and behave the same
way, so learning one means knowing the others:

| Command | What it does | Costs tokens |
|---|---|---|
| `ansforge "<task>"` | the agent, on a task you describe | yes |
| `ansforge scan` | gate one scope — same verdict every time | no |
| `ansforge audit` | report the whole tree, report-only by default | no |
| `ansforge fix` | repair findings, then re-check with the deterministic rules | yes |
| `ansforge version` | | no |

Shared flags on `scan`, `audit` and `fix`:

| Flag | Effect |
|---|---|
| `--json` | machine-readable, so one report can aggregate all three tools |
| `--html [--out FILE]` | a self-contained page: CSS-only tabs, no JavaScript, no external assets, light and dark |
| `--explain` | one batched AI call adding prose and a real before/after per finding — **the only flag that costs tokens** |
| `--fail-on <sev>` | `critical` \| `high` \| `medium` \| `low` \| `info` \| `none` |
| `--top N` | show only the N worst problems |

Why deterministic and agentic are separate commands rather than one clever
entry point: a gate must return the same verdict on the same input, today and
in a year. A model cannot promise that. So the free half decides, and the paid
half advises.

## Install

```sh
# Homebrew
brew install mrg77/tap/ansforge

# or the installer (Linux, macOS)
curl -fsSL https://raw.githubusercontent.com/Mrg77/ansforge/main/install.sh | sh

# or with Go
go install github.com/Mrg77/ansforge@latest
```

Or build from source:

```sh
git clone https://github.com/Mrg77/ansforge && cd ansforge && go build -o ansforge .
```

## Use

```sh
# free, deterministic — no API key needed
ansforge scan .                          # the CI gate: exits 1 on a high finding
ansforge audit .                         # report the tree, report-only
ansforge audit . --html --out health.html
ansforge audit . --json                  # for aggregation

# costs tokens
export ANTHROPIC_API_KEY=...
ansforge audit . --explain               # adds prose + a real before/after per finding
ansforge fix . --diff                    # repairs, then re-checks, and shows the diff
ansforge "render roles/nginx templates with group_vars/all and fix what breaks"
```

`fix` runs headless with a narrow toolset — read, write, re-scan. It cannot run a
playbook: repairing code and changing a machine are different acts, and with no
terminal a `confirm` decision fails closed. The re-check is the deterministic
scanner, never the model's account of its own work.

## The tools

| Tool | What it does |
|---|---|
| `read_file` / `write_file` / `edit_file` | Filesystem, confined to the project root |
| `ansible_lint` | ansible-lint, production profile |
| `ansible_syntax` | `--syntax-check`, parses the playbook and its roles |
| `render_template` | **Renders through Ansible**, with real vars — catches undefined variables a hand-rolled test hides |
| `validate_rendered` | `nginx -t`, `promtool`, `amtool`, `logrotate -d` in a container |
| `security_scan` | Ansible-specific weaknesses, each with its fix |
| `playbook_check` | Dry run (`--check --diff`) |
| `playbook_run` | **Gated** — changes real machines |
| `idempotence_check` | **Gated** — plays twice, requires `changed=0` |

## The guard

In Ansible the destructive act has no frightening name. There is no `destroy`
verb — `ansible-playbook` against an inventory simply changes machines, and it
reads like a routine command. That is exactly why it needs an explicit gate.

The default policy:

| Action | Production context | Elsewhere |
|---|---|---|
| `playbook_run` | **denied** | confirm |
| `idempotence_check` | **denied** | confirm |
| `playbook_check` | confirm | allow |
| lint, render, validate, scan | allow | allow |

Production is detected passively — from the `limit` pattern, the inventory path,
the playbook path — and never by connecting to anything. An unknown context
**fails closed**: a destructive action is not allowed to slip through because the
environment could not be identified. An empty policy file falls back to the
default rather than silently allowing everything.

Read-only tools bypass the policy entirely, so a misconfigured policy can never
stop the agent from merely looking.

## What it will not do

- **It cannot reach your machines on its own.** Every real run is gated, and with
  no TTY (CI, a pipe) a `confirm` becomes a deny.
- **It cannot leave the project.** Every path is confined to the working directory.
  `../../etc/passwd` is an error, not a traversal.
- **It does not claim what it did not check.** When ansible or docker is missing,
  it says the check did not happen. Silence must never read as success.

## Security scan rules

| Rule | Severity | Why |
|---|---|---|
| `plaintext-secret` | high | A credential in clear text in vars |
| `validate-certs-off` | high | TLS verification disabled |
| `download-without-checksum` | high | `get_url` unpinned — a compromised upstream becomes arbitrary code |
| `shell-interpolation` | high | A variable interpolated into `shell` without `\| quote` |
| `no-log-missing` | medium | Ansible logs module arguments, secrets included |
| `world-writable-mode` | medium | The last mode digit grants write to "other" |
| `host-key-checking-off` | medium | A spoofed host would be accepted silently |
| `become-everywhere` | low | Play-level escalation, root for tasks that do not need it |

These heuristics **complement** `ansible-lint`, they do not replace it: a solid
net, not an absolute barrier. Vault references, `lookup()` calls and the `| quote`
filter are recognised as correct and never reported — a scanner that cries wolf on
correct code teaches people to ignore it.

## LLMOps

Every model turn, tool call and guard decision is appended to a JSONL audit log,
with tokens priced per run:

```sh
ANSFORGE_AUDIT=off ansforge "..."        # no file; the summary still prints
ANSFORGE_MAX_COST=0.50 ansforge "..."    # stop before exceeding 0.50 USD
ANSFORGE_MODEL=claude-haiku-4-5 ansforge "..."
```

Reviewability and spend visibility are what make an agent deployable. A run whose
cost you cannot see is a run you cannot budget.

## Licence

MIT.
