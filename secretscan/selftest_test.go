package secretscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Layer 4 (docs/design.md §6).

func TestLayer1SelftestPassesOnTheRealTool(t *testing.T) {
	r, err := Layer1Selftest(gitleaksPath(t), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !r.Pass {
		t.Fatalf("layer 1 self-test failed: %v\n%s", r.Failures, RenderSelftest("layer 1", r))
	}
	if r.Counts["plants found"] < 12 || r.Counts["plants missed"] != 0 || r.Counts["decoys flagged"] != 0 {
		t.Fatalf("counts %v", r.Counts)
	}
	out := RenderSelftest("layer 1", r)
	for _, v := range r.Values {
		if strings.Contains(out, v) {
			t.Fatal("the report carries a planted value")
		}
	}
}

func TestLayer2SelftestCountsAgainstAFakeVornik(t *testing.T) {
	// The fake confirms whatever the deterministic check keeps; the hunters
	// claim the split key's line and the sha decoy's.
	claim := func(path string, line int, class string) map[string]any {
		return map[string]any{"path": wrap(path), "line": line, "class": wrap(class), "reason": wrap("a value")}
	}
	rec := &recordingVornik{out: map[string]map[string]any{
		"hunt-a": {"status": wrap("complete"), "claims": []any{claim("internal/sign/sign.go", 5, "token"), claim("infra/partner.tf", 4, "token")}},
		"hunt-b": {"status": wrap("complete"), "claims": []any{claim("internal/sign/sign.go", 5, "private_key")}},
		"triage": {"status": wrap("complete"), "verdicts": []any{}},
		"adjudicate": {"status": wrap("complete"), "decisions": []any{
			map[string]any{"id": wrap("c01"), "decision": wrap("reject")},
			map[string]any{"id": wrap("c02"), "decision": wrap("confirm")}}, "triage": []any{}},
	}}
	srv := rec.server(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r, err := Layer2Selftest(ctx, &Vornik{URL: srv.URL, Token: "k"}, "ns--x--", gitleaksPath(t), t.TempDir(), Floors{MinDetections: 1, MaxDecoys: 0, Set: true})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Pass || r.Counts["detections"] != 1 || r.Counts["decoys confirmed"] != 0 {
		t.Fatalf("pass %v counts %v failures %v\n%s", r.Pass, r.Counts, r.Failures, RenderSelftest("layer 2", r))
	}
	// Every value layer 1 can find was masked before it was sent; the split
	// key (layer 2's) is meant to reach the reviewers.
	sent := strings.Join(rec.sent, "")
	for _, v := range r.Values[:6] {
		if strings.Contains(sent, v) {
			t.Fatal("a layer 1 plant value was sent to Vornik")
		}
	}
}

func TestSweepNeedsItsControl(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.txt")
	dirty := filepath.Join(dir, "dirty.txt")
	os.WriteFile(clean, []byte("nothing here\n"), 0o644)
	os.WriteFile(dirty, []byte("leaked VALUE-123456 here\n"), 0o644)
	hits, control, err := Sweep([]string{"VALUE-123456"}, []string{clean, dirty}, dir)
	if err != nil || !control || len(hits) != 1 || hits[0] != dirty {
		t.Fatalf("hits %v control %v err %v", hits, control, err)
	}
	if _, _, err := Sweep(nil, []string{clean}, dir); err == nil {
		t.Fatal("a sweep with no values must be an error")
	}
}
