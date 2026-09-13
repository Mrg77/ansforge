// Package mcp exposes a *forge tool's deterministic half over the Model Context
// Protocol, so an assistant (Claude Desktop, Claude Code, Cursor…) can call it
// directly instead of shelling out and parsing text.
//
// What is exposed, and what is not, follows the same line as the CLI: only the
// checks that read. `fix`, the agent, and anything that writes stay out.
//
// The reason is not tidiness. An MCP server is called by a model, usually
// without a human approving each call. Exposing a tool that edits files or
// converges a host would hand an agent the very capability the guards exist to
// withhold — and it would do so through a channel where the policy never runs.
// So the server offers what is free, repeatable and read-only, and nothing else.
//
// Transport is stdio with newline-delimited JSON-RPC 2.0, which is what every
// client supports today.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// protocolVersion is the revision this server implements. Clients send their
// own; we echo a version we actually support rather than theirs blindly.
const protocolVersion = "2025-06-18"

// Tool is one callable exposed to the model.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	// Run returns the text shown to the model, and optionally a structured
	// value. Returning both is recommended by the spec: the text keeps older
	// clients working, the structure is what a model can reason over.
	Run func(args map[string]any) (text string, structured any, err error)
}

// Server serves a fixed tool set over stdio.
type Server struct {
	Name    string
	Version string
	Tools   []Tool
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"` // absent on notifications
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Serve reads requests until stdin closes. Every reply goes to stdout and
// nothing else does: on a stdio transport, a stray Println would corrupt the
// stream, so diagnostics belong on stderr.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // a tool list can be large
	enc := json.NewEncoder(out)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			// Malformed frame: we have no id to answer with, so the spec's
			// null-id parse error is the only correct reply.
			_ = enc.Encode(response{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
			continue
		}
		// A notification has no id and must not be answered at all.
		if len(req.ID) == 0 {
			continue
		}
		resp := s.handle(req)
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func (s *Server) handle(req request) response {
	reply := func(result any) response {
		return response{JSONRPC: "2.0", ID: req.ID, Result: result}
	}
	fail := func(code int, msg string) response {
		return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: code, Message: msg}}
	}

	switch req.Method {
	case "initialize":
		return reply(map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities": map[string]any{
				// listChanged false: the tool set is fixed at build time, so
				// promising notifications we will never send would be a lie.
				"tools": map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{"name": s.Name, "version": s.Version},
		})

	case "tools/list":
		tools := make([]map[string]any, 0, len(s.Tools))
		for _, t := range s.Tools {
			tools = append(tools, map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"inputSchema": t.InputSchema,
			})
		}
		return reply(map[string]any{"tools": tools})

	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fail(-32602, "invalid params")
		}
		for _, t := range s.Tools {
			if t.Name != p.Name {
				continue
			}
			text, structured, err := t.Run(p.Arguments)
			if err != nil {
				// A tool that failed for a reason the model could act on is
				// reported as a result, not a protocol error: the model can
				// read it and retry. A protocol error it can only give up on.
				return reply(map[string]any{
					"content": []content{{Type: "text", Text: err.Error()}},
					"isError": true,
				})
			}
			out := map[string]any{
				"content": []content{{Type: "text", Text: text}},
				"isError": false,
			}
			if structured != nil {
				out["structuredContent"] = structured
			}
			return reply(out)
		}
		return fail(-32602, fmt.Sprintf("unknown tool: %s", p.Name))

	case "ping":
		return reply(map[string]any{})
	}
	return fail(-32601, "method not found: "+req.Method)
}

// Run serves on stdin/stdout and is what the `mcp` subcommand calls.
func (s *Server) Run() int {
	if err := s.Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, s.Name+": mcp:", err)
		return 1
	}
	return 0
}
