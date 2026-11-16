package secretscan

import (
	"crypto/rand"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitleaksPath finds the gitleaks binary these tests drive. They exercise
// the real tool, because its behaviour (skips, columns, counts) is what the
// scan's denominators check; a missing binary fails, never skips.
func gitleaksPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("GITLEAKS"); p != "" {
		return p
	}
	p, err := exec.LookPath("gitleaks")
	if err != nil {
		t.Fatal("gitleaks not found: set GITLEAKS or put it on PATH (scripts/install-gitleaks.sh)")
	}
	return p
}

// fakeToken returns a random GitHub-token-shaped value. It is generated at
// run time, so this file holds no token for a scan of it to find.
func fakeToken(t *testing.T) string {
	t.Helper()
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 36)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alnum))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = alnum[n.Int64()]
	}
	return "gh" + "p_" + string(b)
}

type repo struct {
	t   *testing.T
	dir string
}

func newRepo(t *testing.T) *repo {
	t.Helper()
	r := &repo{t: t, dir: t.TempDir()}
	r.git("init", "-q", "-b", "main")
	r.git("config", "user.email", "test@example.invalid")
	r.git("config", "user.name", "test")
	return r
}

func (r *repo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *repo) write(path, content string) {
	r.t.Helper()
	full := filepath.Join(r.dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *repo) commit(msg string) string {
	r.t.Helper()
	r.git("add", "-A")
	r.git("commit", "-q", "-m", msg)
	return r.git("rev-parse", "HEAD")
}

func scanOpts(t *testing.T, r *repo, base, head string) Options {
	return Options{
		Repo:        r.dir,
		Base:        base,
		Head:        head,
		Gitleaks:    gitleaksPath(t),
		AccountVars: []string{"154480844551"},
		WorkDir:     t.TempDir(),
	}
}

func byRule(fs []Finding) map[string][]string {
	m := map[string][]string{}
	for _, f := range fs {
		m[f.Rule] = append(m[f.Rule], f.Path)
	}
	return m
}

func TestScanCleanRepository(t *testing.T) {
	r := newRepo(t)
	r.write("main.go", "package main\n\nfunc main() {}\n")
	base := r.commit("initial")
	r.write("README.md", "# demo\n")
	head := r.commit("add readme")

	res, err := Scan(scanOpts(t, r, base, head))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("clean repository: findings %v", res.Findings)
	}
	if res.Tree.TrackedFiles != 2 || res.Tree.ScannedBytes == 0 {
		t.Fatalf("tree denominator %+v", res.Tree)
	}
	if res.RangeCommits != 1 || res.HistoryCommits != 2 {
		t.Fatalf("commit counts: range %d, history %d", res.RangeCommits, res.HistoryCommits)
	}
}

func TestScanFindsEveryPlantedKind(t *testing.T) {
	r := newRepo(t)
	r.write("main.go", "package main\n")
	r.write("infra/a.tf", "x = 1 # "+marker+"\n")
	base := r.commit("initial")

	tok := fakeToken(t)
	r.write("config/app.env.sample", "TOKEN="+tok+"\n")                        // gitleaks-class
	r.write("infra/db.tf", fakeDBURL+"\n")                                     // url-password
	r.write("infra/partner.tf", `partner = "359545463725"`+"\n")               // account-id
	r.write("deploy/server.key", "not really a key\n")                         // key-file
	r.write("certs/k.txt", "-----"+"BEGIN PRIVATE KEY-----\n")                 // pem
	r.write("infra/b.tf", "y = 2 # "+marker+" a fixture that fires nothing\n") // marker silences nothing
	r.write("data/blob.bin", "\x00\x01binary\x00TOKEN="+fakeToken(t)+"\n")     // binary: stdin rescan
	r.write("notes/dir_"+fakeToken(t)+"/f.txt", "x\n")                         // token in a path
	head := r.commit("add things; token " + fakeToken(t))                      // token in a message

	res, err := Scan(scanOpts(t, r, base, head))
	if err != nil {
		t.Fatal(err)
	}
	got := byRule(res.Findings)
	for _, want := range []struct{ rule, pathPart string }{
		{"github-pat", "config/app.env.sample"},
		{RuleURLPassword, "infra/db.tf"},
		{RuleAccountID, "infra/partner.tf"},
		{RuleKeyFile, "deploy/server.key"},
		{RulePEMKey, "certs/k.txt"},
		{RuleMarkerNoReason, "infra/a.tf"},
		{RuleMarkerSilencesNothing, "infra/b.tf"},
		{"github-pat", "data/blob.bin"},
		{"github-pat", PathListName},
		{"github-pat", CommitMessagesName},
	} {
		found := false
		for _, p := range got[want.rule] {
			if strings.Contains(p, want.pathPart) {
				found = true
			}
		}
		if !found {
			t.Errorf("no %s finding at %s; findings: %v", want.rule, want.pathPart, res.Findings)
		}
	}
	for _, f := range res.Findings {
		if strings.Contains(f.String(), "gh"+"p_") {
			t.Fatalf("finding %q carries a token", f.String())
		}
	}
}

func TestScanRefusesAnEmptyRepository(t *testing.T) {
	r := newRepo(t)
	r.git("commit", "-q", "--allow-empty", "-m", "empty")
	if _, err := Scan(scanOpts(t, r, "", "")); err == nil {
		t.Fatal("an empty tree must be an error, never clean")
	}
}

// A clone too shallow to hold the history fails: gitleaks would scan the
// commits it has and report clean (docs/design.md §3).
func TestScanRefusesAShallowClone(t *testing.T) {
	r := newRepo(t)
	r.write("a.go", "package a\n")
	r.commit("one")
	r.write("b.go", "package a\n")
	r.commit("two")
	shallow := t.TempDir()
	cmd := exec.Command("git", "clone", "-q", "--depth", "1", "file://"+r.dir, shallow)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	o := scanOpts(t, &repo{t: t, dir: shallow}, "", "")
	// git and gitleaks see the same truncated history, so their counts
	// agree; only asking git whether the clone is shallow catches it.
	if _, err := Scan(o); err == nil || !strings.Contains(err.Error(), "shallow") {
		t.Fatalf("a depth-1 clone must be refused as shallow, got %v", err)
	}
}

func TestDiffHelpers(t *testing.T) {
	if got := hunkStart("@@ -10,3 +12,8 @@ func x() {"); got != 12 {
		t.Fatalf("hunkStart = %d", got)
	}
	if got := hunkStart("not a hunk"); got != 0 {
		t.Fatalf("hunkStart(junk) = %d", got)
	}
	if got := binaryPath("Binary files /dev/null and b/data/x.bin differ"); got != "data/x.bin" {
		t.Fatalf("binaryPath = %q", got)
	}
	if got := binaryPath("+ordinary line"); got != "" {
		t.Fatalf("binaryPath(junk) = %q", got)
	}
}

func TestScanRequiresItsOptions(t *testing.T) {
	if _, err := Scan(Options{}); err == nil {
		t.Fatal("empty options must be an error")
	}
}
