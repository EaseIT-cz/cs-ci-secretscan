package secretscan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func wrap(s string) string { return wrapOpen + s + wrapClose }

func TestUnwrap(t *testing.T) {
	if got, err := Unwrap(wrap("token")); err != nil || got != "token" {
		t.Fatalf("Unwrap = %q, %v", got, err)
	}
	for _, bad := range []string{"token", "<untrusted_content>token</untrusted_content>", wrap(wrap("x")), wrapOpen} {
		if _, err := Unwrap(bad); err == nil {
			t.Errorf("Unwrap(%q) accepted a wrong shape", bad)
		}
	}
}

// fakeVornik answers delegate and result as the companion endpoint does.
func fakeVornik(t *testing.T, outputs map[string]map[string]any) (*httptest.Server, *[]string) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		_ = json.Unmarshal(raw, &req)
		var text string
		switch req.Params.Name {
		case "delegate":
			wf := req.Params.Arguments["workflow"].(string)
			seen = append(seen, wf)
			text = `{"task_id":"task-` + wf + `"}`
		case "result":
			wf := strings.TrimPrefix(req.Params.Arguments["task_id"].(string), "task-")
			out, _ := json.Marshal(map[string]any{"complete": true, "status": "COMPLETED", "output": outputs[wf]})
			text = string(out)
		}
		resp, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []map[string]string{{"type": "text", "text": text}}}})
		w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestVornikDelegateAndWait(t *testing.T) {
	srv, seen := fakeVornik(t, map[string]map[string]any{
		"wf-hunt": {"status": wrap("complete"), "files_examined": 2, "claims": []any{map[string]any{"path": wrap("a.go"), "line": 3, "class": wrap("token"), "reason": wrap("a key")}}},
	})
	v := &Vornik{URL: srv.URL, Token: "test-key"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	task, err := v.Delegate(ctx, "wf-hunt", map[string]any{"diff": "x"})
	if err != nil || task != "task-wf-hunt" {
		t.Fatalf("Delegate = %q, %v", task, err)
	}
	out, err := v.Wait(ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	var h huntOutput
	if err := decode(out, &h); err != nil || h.Status != "complete" || len(h.Claims) != 1 || h.Claims[0].Path != "a.go" {
		t.Fatalf("decoded %+v, %v", h, err)
	}
	if len(*seen) != 1 {
		t.Fatalf("delegations %v", *seen)
	}
}

func TestVornikRefusesAWrongKeyAndAnUnwrappedString(t *testing.T) {
	srv, _ := fakeVornik(t, map[string]map[string]any{"wf": {"status": "complete"}})
	ctx := context.Background()
	if _, err := (&Vornik{URL: srv.URL, Token: "wrong"}).Delegate(ctx, "wf", nil); err == nil {
		t.Fatal("a refused key must be an error")
	}
	v := &Vornik{URL: srv.URL, Token: "test-key"}
	task, _ := v.Delegate(ctx, "wf", nil)
	if _, err := v.Wait(ctx, task); err == nil {
		t.Fatal("an unwrapped string must be refused")
	}
}
