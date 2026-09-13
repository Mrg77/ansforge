package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Mrg77/ansforge/internal/mcp"
	"github.com/Mrg77/ansforge/internal/report"
	"github.com/Mrg77/ansforge/internal/tools"
)

// runMCP serves the deterministic checks over the Model Context Protocol, so an
// assistant can call them directly instead of shelling out and parsing text.
//
// Only the read-only half is exposed. An MCP server is driven by a model,
// usually without a human approving each call: handing it `fix` would give an
// agent the ability to rewrite files through a channel where the CLI's guard
// never runs. What is offered here is free, repeatable, and changes nothing.
func runMCP(args []string) int {
	root := "."
	if len(args) > 0 {
		root = args[0]
	}
	if abs, err := os.Getwd(); err == nil && root == "." {
		root = abs
	}
	tools.SetProjectRoot(root)

	pathSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{
				"type":        "string",
				"description": "Directory to analyse, relative to the project root. Defaults to the whole project.",
			},
		},
		"additionalProperties": false,
	}

	scan := func(args map[string]any) (string, any, error) {
		path, _ := args["path"].(string)
		if path == "" {
			path = "."
		}
		findings, err := tools.Scan(path)
		if err != nil {
			return "", nil, err
		}
		r := &report.Report{Tool: "ansforge", Subject: path, Findings: findings}
		r.Sort()
		// Text for clients that only render content; the structure for the
		// model to reason over. The spec recommends returning both.
		var out struct {
			Count       int              `json:"count"`
			MaxSeverity string           `json:"max_severity"`
			Findings    []report.Finding `json:"findings"`
		}
		out.Count = len(findings)
		out.MaxSeverity = string(r.Worst())
		if out.MaxSeverity == "" {
			out.MaxSeverity = "none"
		}
		out.Findings = r.Findings
		var structured any
		b, _ := json.Marshal(out)
		_ = json.Unmarshal(b, &structured)
		return r.Text(0), structured, nil
	}

	srv := &mcp.Server{
		Name:    "ansforge",
		Version: version,
		Tools: []mcp.Tool{
			{
				Name: "ansible_scan",
				Description: "Scan Ansible content for security issues: plain-text credentials, missing no_log, " +
					"downloads without a pinned checksum, shell interpolation, over-broad become, world-writable " +
					"modes. Deterministic and read-only — it changes nothing and costs nothing to call.",
				InputSchema: pathSchema,
				Run:         scan,
			},
			{
				Name: "ansible_audit",
				Description: "Same checks as ansible_scan, over a whole tree, returned worst-first with a count " +
					"per severity. Use this to answer \"what is wrong with this repository\"; use ansible_scan " +
					"when you care about one directory.",
				InputSchema: pathSchema,
				Run:         scan,
			},
		},
	}

	fmt.Fprintf(os.Stderr, "ansforge mcp · serving %d read-only tool(s) on stdio · root %s\n", len(srv.Tools), root)
	return srv.Run()
}
