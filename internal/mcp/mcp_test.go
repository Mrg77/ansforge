package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func testServer() *Server {
	return &Server{
		Name: "ansforge", Version: "test",
		Tools: []Tool{{
			Name:        "scan",
			Description: "Scan a path.",
			InputSchema: map[string]any{"type": "object", "additionalProperties": false},
			Run: func(args map[string]any) (string, any, error) {
				if bad, _ := args["fail"].(bool); bad {
					return "", nil, fmt.Errorf("path not found")
				}
				return "3 findings", map[string]any{"count": 3}, nil
			},
		}},
	}
}

// exchange sends one request line and returns the decoded reply.
func exchange(t *testing.T, s *Server, line string) map[string]any {
	t.Helper()
	var out strings.Builder
	if err := s.Serve(strings.NewReader(line+"\n"), &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if out.Len() == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out.String()), &m); err != nil {
		t.Fatalf("reply is not valid JSON: %v\n%s", err, out.String())
	}
	return m
}

func TestInitializeAnnouncesVersionAndTools(t *testing.T) {
	m := exchange(t, testServer(), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	r, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", m)
	}
	if r["protocolVersion"] != protocolVersion {
		t.Fatalf("protocolVersion: want %s, got %v", protocolVersion, r["protocolVersion"])
	}
	caps := r["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Fatal("a server exposing tools must declare the tools capability")
	}
	// Promising listChanged we never send would make a client wait for
	// notifications that are not coming.
	if caps["tools"].(map[string]any)["listChanged"] != false {
		t.Fatal("listChanged must be false: the tool set is fixed at build time")
	}
}

func TestToolsListShape(t *testing.T) {
	m := exchange(t, testServer(), `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools := m["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("want 1 tool, got %d", len(tools))
	}
	tool := tools[0].(map[string]any)
	for _, k := range []string{"name", "description", "inputSchema"} {
		if _, ok := tool[k]; !ok {
			t.Fatalf("a tool definition requires %q", k)
		}
	}
	// A null or missing schema makes some clients drop the tool entirely.
	if _, ok := tool["inputSchema"].(map[string]any)["type"]; !ok {
		t.Fatal("inputSchema must be a JSON Schema object with a type")
	}
}

func TestCallReturnsTextAndStructure(t *testing.T) {
	m := exchange(t, testServer(),
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan","arguments":{}}}`)
	r := m["result"].(map[string]any)
	if r["isError"] != false {
		t.Fatalf("a successful call must not be flagged as an error: %v", r)
	}
	c := r["content"].([]any)[0].(map[string]any)
	if c["type"] != "text" || c["text"] != "3 findings" {
		t.Fatalf("unexpected content: %v", c)
	}
	// Text keeps older clients working; the structure is what a model reasons over.
	if r["structuredContent"].(map[string]any)["count"].(float64) != 3 {
		t.Fatalf("structuredContent missing or wrong: %v", r["structuredContent"])
	}
}

// A tool that failed for a reason the model could act on is a RESULT with
// isError, not a protocol error — the model can read it and retry.
func TestToolFailureIsAResultNotAProtocolError(t *testing.T) {
	m := exchange(t, testServer(),
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"scan","arguments":{"fail":true}}}`)
	if _, isProtocolError := m["error"]; isProtocolError {
		t.Fatal("a tool failure must not surface as a JSON-RPC error")
	}
	r := m["result"].(map[string]any)
	if r["isError"] != true {
		t.Fatal("a failed tool call must set isError")
	}
	if !strings.Contains(r["content"].([]any)[0].(map[string]any)["text"].(string), "path not found") {
		t.Fatal("the reason must reach the model so it can correct itself")
	}
}

func TestUnknownToolIsAProtocolError(t *testing.T) {
	m := exchange(t, testServer(),
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope","arguments":{}}}`)
	e, ok := m["error"].(map[string]any)
	if !ok {
		t.Fatalf("an unknown tool is a protocol error: %v", m)
	}
	if e["code"].(float64) != -32602 {
		t.Fatalf("want -32602, got %v", e["code"])
	}
}

func TestUnknownMethodIsRejected(t *testing.T) {
	m := exchange(t, testServer(), `{"jsonrpc":"2.0","id":6,"method":"resources/list"}`)
	if m["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Fatalf("want method-not-found: %v", m)
	}
}

// A notification has no id and must produce no reply at all. Answering one
// desynchronises a client that is not expecting a frame.
func TestNotificationGetsNoReply(t *testing.T) {
	if m := exchange(t, testServer(), `{"jsonrpc":"2.0","method":"notifications/initialized"}`); m != nil {
		t.Fatalf("a notification must not be answered, got %v", m)
	}
}

func TestMalformedFrameGetsParseError(t *testing.T) {
	m := exchange(t, testServer(), `{not json`)
	if m["error"].(map[string]any)["code"].(float64) != -32700 {
		t.Fatalf("want parse error -32700: %v", m)
	}
}

// Several frames in one stream must each get exactly one reply, in order.
func TestMultipleRequestsInSequence(t *testing.T) {
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	}, "\n")
	var out strings.Builder
	if err := testServer().Serve(strings.NewReader(in+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 replies (the notification is silent), got %d:\n%s", len(lines), out.String())
	}
}
