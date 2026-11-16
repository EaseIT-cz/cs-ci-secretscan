package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
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
