package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitleaksBin(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("GITLEAKS"); p != "" {
		return p
	}
	p, err := exec.LookPath("gitleaks")
	if err != nil {
		t.Fatal("gitleaks not found: set GITLEAKS or put it on PATH")
	}
	return p
}

func repoWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q", "-b", "main")
	git("config", "user.email", "test@example.invalid")
	git("config", "user.name", "test")
	for p, c := range files {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("add", "-A")
	git("commit", "-q", "-m", "initial")
	return dir
}

func TestUsageIsExitTwo(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("no arguments: exit %d, want 2", code)
	}
	if code := run([]string{"scan", "--no-such-flag"}, &out, &errb); code != 2 {
		t.Fatalf("bad flag: exit %d, want 2", code)
	}
}

func TestCleanRepositoryIsExitZero(t *testing.T) {
	dir := repoWith(t, map[string]string{"main.go": "package main\n"})
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--repo", dir, "--gitleaks", gitleaksBin(t)}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s%s", code, out.String(), errb.String())
	}
	for _, want := range []string{"tracked files | 1", "No findings", "accounts.allow: not given"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, out.String())
		}
	}
}

func TestFindingIsExitOneAndNoValueIsPrinted(t *testing.T) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	tok := "gh" + "p_" + hex.EncodeToString(b) // 36 characters after the prefix
	dir := repoWith(t, map[string]string{"app.cfg": "token = " + tok + "\n"})
	report := filepath.Join(t.TempDir(), "layer1.jsonl")
	summary := filepath.Join(t.TempDir(), "summary.md")
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--repo", dir, "--gitleaks", gitleaksBin(t), "--report", report, "--summary", summary}, &out, &errb)
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s%s", code, out.String(), errb.String())
	}
	rep, _ := os.ReadFile(report)
	sum, _ := os.ReadFile(summary)
	for name, text := range map[string]string{"stdout": out.String(), "stderr": errb.String(), "report": string(rep), "summary": string(sum)} {
		if strings.Contains(text, tok) || strings.Contains(text, tok[4:20]) {
			t.Errorf("%s carries the token", name)
		}
	}
	if !strings.Contains(string(rep), `"path":"app.cfg"`) {
		t.Errorf("report lacks the finding's path: %s", rep)
	}
}

func TestMalformedLedgerIsExitTwo(t *testing.T) {
	dir := repoWith(t, map[string]string{"main.go": "package main\n"})
	led := t.TempDir()
	if err := os.WriteFile(filepath.Join(led, "accounts.allow"), []byte("no tab here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--repo", dir, "--gitleaks", gitleaksBin(t), "--ledgers", led}, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}

// A relative --gitleaks or --repo is resolved before any command runs in
// another directory (found running the repository's own scan).
func TestRelativePathsWork(t *testing.T) {
	dir := repoWith(t, map[string]string{"main.go": "package main\n"})
	bin := gitleaksBin(t)
	t.Chdir(filepath.Dir(bin))
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--repo", dir, "--gitleaks", "./" + filepath.Base(bin)}, &out, &errb); code != 0 {
		t.Fatalf("relative --gitleaks: exit %d\n%s", code, errb.String())
	}
	t.Chdir(dir)
	if code := run([]string{"scan", "--repo", ".", "--gitleaks", bin}, &out, &errb); code != 0 {
		t.Fatalf("relative --repo: exit %d\n%s", code, errb.String())
	}
}

func TestReviewUsageAndFailOpen(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"review", "--repo", "."}, &out, &errb); code != 2 {
		t.Fatalf("review without --base: exit %d, want 2", code)
	}
	dir := repoWith(t, map[string]string{"a.go": "package a\n"})
	t.Setenv("VORNIK_TOKEN", "")
	out.Reset()
	code := run([]string{"review", "--repo", dir, "--base", "HEAD", "--vornik-url", "http://127.0.0.1:1", "--prefix", "p--", "--gitleaks", gitleaksBin(t)}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "did not complete") {
		t.Fatalf("no key: exit %d, want 0 with a did-not-complete comment:\n%s", code, out.String())
	}
}

func TestCommentRefusesWhatReviewDidNotWrite(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c.md")
	os.WriteFile(f, []byte("hello, not a review comment"), 0o644)
	var errb bytes.Buffer
	if code := run([]string{"comment", "--file", f, "--pr", "1", "--repository", "o/r"}, io.Discard, &errb); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if code := run([]string{"comment"}, io.Discard, &errb); code != 2 {
		t.Fatalf("usage: exit %d, want 2", code)
	}
}

func TestSelftestLayer1AndSweepCommands(t *testing.T) {
	dir := t.TempDir()
	values := filepath.Join(dir, "values")
	out := filepath.Join(dir, "out.txt")
	f, _ := os.Create(out)
	code := run([]string{"selftest", "layer1", "--gitleaks", gitleaksBin(t), "--values", values}, f, io.Discard)
	f.Close()
	if code != 0 {
		b, _ := os.ReadFile(out)
		t.Fatalf("selftest layer1: exit %d\n%s", code, b)
	}
	var sw bytes.Buffer
	if code := run([]string{"sweep", "--values", values, out}, &sw, io.Discard); code != 0 {
		t.Fatalf("sweep of the self-test's own output: exit %d\n%s", code, sw.String())
	}
	if !strings.Contains(sw.String(), "positive control found: true") {
		t.Fatalf("sweep: %s", sw.String())
	}
	if code := run([]string{"sweep", "--values", values, values}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("a sweep of the values file itself must find them: exit %d", code)
	}
}

func TestReadFloors(t *testing.T) {
	f, err := readFloors(filepath.Join(t.TempDir(), "absent.env"))
	if err != nil || f.Set {
		t.Fatalf("absent file: %+v %v", f, err)
	}
	p := filepath.Join(t.TempDir(), "floors.env")
	os.WriteFile(p, []byte("# set after four weekly runs\nFLOOR_DETECTIONS=1\nCEILING_DECOYS=0\n"), 0o644)
	if f, err = readFloors(p); err != nil || !f.Set || f.MinDetections != 1 || f.MaxDecoys != 0 {
		t.Fatalf("floors %+v %v", f, err)
	}
	os.WriteFile(p, []byte("FLOOR_DETECTIONS=1\n"), 0o644)
	if f, _ = readFloors(p); f.Set {
		t.Fatal("one key alone does not set the floors")
	}
	os.WriteFile(p, []byte("FLOOR_DETECTIONS=many\nCEILING_DECOYS=0\n"), 0o644)
	if _, err = readFloors(p); err == nil {
		t.Fatal("a non-number must be an error")
	}
}

func TestLayer4UsageErrors(t *testing.T) {
	t.Setenv("VORNIK_TOKEN", "")
	for _, args := range [][]string{
		{"selftest"},
		{"selftest", "layer3"},
		{"selftest", "layer2", "--vornik-url", "http://x", "--prefix", "p"},
		{"sweep"},
		{"completion"},
	} {
		if code := run(args, io.Discard, io.Discard); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

// The self-test with a relative --gitleaks, as CI passes it (found at:
// e2e-lane, the first scheduled run: the corpus ran gitleaks from its own
// directory and could not start it; the third bug of this class, so every
// gitleaks run now resolves its path itself).
func TestSelftestWithARelativeGitleaksPath(t *testing.T) {
	bin := gitleaksBin(t)
	t.Chdir(filepath.Dir(bin))
	var out, errb bytes.Buffer
	if code := run([]string{"selftest", "layer1", "--gitleaks", "./" + filepath.Base(bin)}, &out, &errb); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
	}
}
