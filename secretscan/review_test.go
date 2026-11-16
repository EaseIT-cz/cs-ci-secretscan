package secretscan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingVornik answers the four workflows and records every input it
// is sent, so a test can assert what left the runner.
type recordingVornik struct {
	mu   sync.Mutex
	sent []string
	out  map[string]map[string]any
}

func (rv *recordingVornik) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			rv.mu.Lock()
			rv.sent = append(rv.sent, string(raw))
			rv.mu.Unlock()
			wf := req.Params.Arguments["workflow"].(string)
			text = `{"task_id":"` + wf + `"}`
		case "result":
			wf := req.Params.Arguments["task_id"].(string)
			key := wf[strings.LastIndex(wf, "--")+2:]
			out, _ := json.Marshal(map[string]any{"complete": true, "status": "COMPLETED", "output": rv.out[key]})
			text = string(out)
		}
		resp, _ := json.Marshal(map[string]any{"result": map[string]any{"content": []map[string]string{{"text": text}}}})
		w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRunReviewSendsOnlyMaskedTextAndConfirmsTheSplitKey(t *testing.T) {
	r := newRepo(t)
	r.write("main.go", "package main\n")
	base := r.commit("base")
	tok := fakeToken(t)
	r.write("main.go", "package main\n\nconst t = \""+tok+"\"\n\nvar part1 = \"a39e382dd4865c0bd3ad\"\nvar part2 = \"514e68cc07642da67d76\"\n")
	head := r.commit("change")

	claim := func(line int, class, reason string) map[string]any {
		return map[string]any{"path": wrap("main.go"), "line": line, "class": wrap(class), "reason": wrap(reason)}
	}
	rec := &recordingVornik{out: map[string]map[string]any{
		"hunt-a": {"status": wrap("complete"), "claims": []any{claim(5, "token", "first half of a split key")}},
		"hunt-b": {"status": wrap("complete"), "claims": []any{claim(5, "api_key", "a key split across two literals")}},
		"triage": {"status": wrap("complete"), "verdicts": []any{}},
		"adjudicate": {"status": wrap("complete"), "decisions": []any{
			map[string]any{"id": wrap("c01"), "decision": wrap("confirm")}}, "triage": []any{}},
	}}
	srv := rec.server(t)
	o := ReviewOptions{
		Scan:    scanOpts(t, r, base, head),
		Vornik:  &Vornik{URL: srv.URL, Token: "test-key"},
		Prefix:  "ns--secretscan--",
		HeadSHA: head,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rv := RunReview(ctx, o)
	if !rv.Completed {
		t.Fatalf("review did not complete: %s", rv.Reason)
	}
	if len(rec.sent) != 4 {
		t.Fatalf("sent %d workflow calls, want 4 (three at once, then adjudicate)", len(rec.sent))
	}
	for _, s := range rec.sent {
		if strings.Contains(s, tok) || strings.Contains(s, tok[4:16]) {
			t.Fatal("a value layer 1 found was sent to Vornik")
		}
	}
	if !strings.Contains(strings.Join(rec.sent, ""), "a39e382dd4865c0bd3ad") {
		t.Fatal("the split key (which layer 1 cannot see) should reach the reviewers")
	}
	if len(rv.Findings) != 1 || rv.Findings[0].Confidence != "high" || rv.Findings[0].FoundBy != "both" {
		t.Fatalf("findings %+v", rv.Findings)
	}
	c := RenderComment(rv, 0, 0)
	if !strings.Contains(c, CommentMarker) || !strings.Contains(c, "| high |") || strings.Contains(c, tok) {
		t.Fatalf("comment:\n%s", c)
	}
}

func TestRunReviewFailsOpenWhenVornikIsDown(t *testing.T) {
	r := newRepo(t)
	r.write("a.go", "package a\n")
	base := r.commit("base")
	r.write("a.go", "package a\n\nvar x = 1\n")
	head := r.commit("change")
	o := ReviewOptions{Scan: scanOpts(t, r, base, head), Vornik: &Vornik{URL: "http://127.0.0.1:1/none", Token: "k"}, Prefix: "p--", HeadSHA: head}
	rv := RunReview(context.Background(), o)
	if rv.Completed {
		t.Fatal("with Vornik down the review cannot complete")
	}
	if c := RenderComment(rv, 0, 0); !strings.Contains(c, "did not complete") {
		t.Fatalf("comment does not say so:\n%s", c)
	}
}

// When the base branch moved on after the change branched, the change's
// diff is from their merge base: base..head would also show the base's
// later changes, reversed, as if the change made them (found writing the
// pull_request_target workflow).
func TestChangeDiffIsFromTheMergeBase(t *testing.T) {
	r := newRepo(t)
	r.write("a.go", "package a\n")
	r.commit("root")
	r.git("checkout", "-q", "-b", "feature")
	r.write("b.go", "package a\n\nvar fromTheChange = 1\n")
	head := r.commit("change")
	r.git("checkout", "-q", "main")
	r.write("c.go", "package a\n\nvar fromTheBase = 2\n")
	base := r.commit("base moved on")
	d, _, err := changeDiff(Options{Repo: r.dir, Base: base, Head: head}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d, "fromTheChange") || strings.Contains(d, "fromTheBase") {
		t.Fatalf("diff is not the change's alone:\n%s", d)
	}
}
