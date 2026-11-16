package secretscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Vornik calls Vornik's companion MCP endpoint (JSON-RPC over HTTP) with a
// companion key, to run broker workflows and read their results.
type Vornik struct {
	URL    string // e.g. https://vornik.example/api/v1/mcp/companion
	Token  string // a companion key; sent only as a bearer header
	Client *http.Client
}

// maxResponse caps what is read from Vornik.
const maxResponse = 1 << 20

func (v *Vornik) client() *http.Client {
	if v.Client != nil {
		return v.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// call invokes one MCP tool and returns its first text content.
func (v *Vornik) call(ctx context.Context, tool string, args any) (string, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args},
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.URL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+v.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := v.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("vornik %s: %w", tool, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return "", fmt.Errorf("vornik %s: %w", tool, err)
	}
	if len(raw) > maxResponse {
		return "", fmt.Errorf("vornik %s: response over %d bytes", tool, maxResponse)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vornik %s: HTTP %d", tool, resp.StatusCode)
	}
	var r struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("vornik %s: unreadable response", tool)
	}
	if r.Error != nil {
		return "", fmt.Errorf("vornik %s: %s", tool, firstLine(r.Error.Message))
	}
	if len(r.Result.Content) == 0 {
		return "", fmt.Errorf("vornik %s: empty result", tool)
	}
	if r.Result.IsError {
		return "", fmt.Errorf("vornik %s: %s", tool, firstLine(r.Result.Content[0].Text))
	}
	return r.Result.Content[0].Text, nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// Delegate starts a broker workflow with typed inputs; it returns the task.
func (v *Vornik) Delegate(ctx context.Context, workflow string, inputs map[string]any) (string, error) {
	text, err := v.call(ctx, "delegate", map[string]any{"workflow": workflow, "inputs": inputs})
	if err != nil {
		return "", err
	}
	var r struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal([]byte(text), &r); err != nil || r.TaskID == "" {
		return "", fmt.Errorf("vornik delegate %s: no task id", workflow)
	}
	return r.TaskID, nil
}

// Wait polls a task until it completes or ctx ends, and returns its
// output with Vornik's untrusted-content wrapper stripped.
func (v *Vornik) Wait(ctx context.Context, task string) (map[string]any, error) {
	for {
		text, err := v.call(ctx, "result", map[string]any{"task_id": task, "wait_seconds": 25})
		if err != nil {
			return nil, err
		}
		var r struct {
			Complete    bool           `json:"complete"`
			Status      string         `json:"status"`
			Output      map[string]any `json:"output"`
			EgressError string         `json:"egress_error"`
		}
		if err := json.Unmarshal([]byte(text), &r); err != nil {
			return nil, fmt.Errorf("vornik result: unreadable")
		}
		if r.Complete {
			if r.EgressError != "" {
				return nil, fmt.Errorf("Vornik withheld its output (%s)", firstLine(r.EgressError))
			}
			if r.Status != "COMPLETED" || r.Output == nil {
				return nil, fmt.Errorf("vornik task ended %s with no output", r.Status)
			}
			out, err := unwrapAll(r.Output)
			if err != nil {
				return nil, err
			}
			return out.(map[string]any), nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("vornik task: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

const (
	wrapOpen  = "<untrusted_content source=\"broker_egress\">\n"
	wrapClose = "\n</untrusted_content>"
)

// Unwrap strips exactly Vornik's broker-egress wrapper from one string and
// refuses any other shape (docs/design.md §4).
func Unwrap(s string) (string, error) {
	if !strings.HasPrefix(s, wrapOpen) || !strings.HasSuffix(s, wrapClose) || len(s) < len(wrapOpen)+len(wrapClose) {
		return "", errors.New("vornik: a returned string is not in the broker-egress wrapper")
	}
	inner := s[len(wrapOpen) : len(s)-len(wrapClose)]
	if strings.Contains(inner, "untrusted_content") {
		return "", errors.New("vornik: a nested wrapper in a returned string")
	}
	return inner, nil
}

func unwrapAll(v any) (any, error) {
	switch x := v.(type) {
	case string:
		return Unwrap(x)
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			u, err := unwrapAll(e)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out[k] = u
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			u, err := unwrapAll(e)
			if err != nil {
				return nil, err
			}
			out[i] = u
		}
		return out, nil
	default:
		return v, nil
	}
}

// decode re-marshals an unwrapped output into a typed value.
func decode(out map[string]any, into any) error {
	raw, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}
