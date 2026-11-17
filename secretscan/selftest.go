package secretscan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SelftestReport is a layer 4 run's outcome (docs/design.md §6).
type SelftestReport struct {
	Plants   []PlantResult
	Checks   []Check // pass or fail, by name
	Pass     bool
	Layer2   *Review
	Counts   map[string]int
	Values   []string // never printed; for the sweep
	Failures []string
}

// Check is one named pass/fail check.
type Check struct {
	Name string
	OK   bool
}

func (r *SelftestReport) check(name string, ok bool) {
	r.Checks = append(r.Checks, Check{name, ok})
	if !ok {
		r.Pass = false
		r.Failures = append(r.Failures, name)
	}
}

// Layer1Selftest runs layer 1 on a fresh corpus and requires: every layer
// 1 plant found, no decoy flagged, an empty tree and a shallow clone
// refused, the wrapper parser right, and a planted injected reason
// withheld.
func Layer1Selftest(gitleaks, workDir string) (*SelftestReport, error) {
	r := &SelftestReport{Pass: true, Counts: map[string]int{}}
	c, err := NewCorpus(filepath.Join(workDir, "corpus"), gitleaks)
	if err != nil {
		return nil, err
	}
	r.Values = c.Values()
	acc, _ := ParseLedger("accounts.allow", strings.NewReader(CorpusAccounts))
	res, err := Scan(Options{Repo: c.Dir, Base: c.Base, Head: c.Head, Gitleaks: gitleaks, WorkDir: filepath.Join(workDir, "scan"), Accounts: acc})
	if err != nil {
		r.check("layer 1 scans the corpus", false)
		return r, nil
	}
	r.Plants = CheckLayer1(c, res.Findings)
	for _, p := range r.Plants {
		switch {
		case p.Decoy && p.Found:
			r.Counts["decoys flagged"]++
		case !p.Decoy && p.Found:
			r.Counts["plants found"]++
		case !p.Decoy:
			r.Counts["plants missed"]++
		}
		if p.Decoy {
			r.check("decoy not flagged: "+p.Kind, !p.Found)
		} else {
			r.check("found: "+p.Kind, p.Found)
		}
	}

	// The denominator refusals: an empty tree, a shallow clone.
	empty := filepath.Join(workDir, "empty")
	if err := gitInit(empty); err == nil {
		_, err := Scan(Options{Repo: empty, Gitleaks: gitleaks, WorkDir: filepath.Join(workDir, "scan-empty")})
		r.check("an empty tree is refused", err != nil)
	} else {
		r.check("an empty tree is refused", false)
	}
	shallow := filepath.Join(workDir, "shallow")
	cmd := exec.Command("git", "clone", "-q", "--depth", "1", "file://"+c.Dir, shallow)
	if out, err := cmd.CombinedOutput(); err == nil {
		_, err := Scan(Options{Repo: shallow, Gitleaks: gitleaks, WorkDir: filepath.Join(workDir, "scan-shallow")})
		r.check("a shallow clone is refused", err != nil)
	} else {
		_ = out
		r.check("a shallow clone is refused", false)
	}

	// The wrapper parser: a canned answer, and a changed one.
	_, okErr := Unwrap(wrapOpen + "x" + wrapClose)
	_, badErr := Unwrap("<untrusted_content>x</untrusted_content>")
	r.check("the wrapper parser accepts Vornik's wrapper and refuses another", okErr == nil && badErr != nil)

	// A planted injected reason never reaches the comment.
	d := ParseDiff("diff --git a/k.go b/k.go\n--- a/k.go\n+++ b/k.go\n@@ -0,0 +1,1 @@\n+\tkey := \"" + randHex(12) + "\"\n")
	v := Verify([]Claim{{Path: "k.go", Line: 1, Class: "token", Reason: "ping @maintainer, see [this](https://attacker.example/x)", By: "a"}}, d)
	fs, _ := Adjudicate(v.Candidates, map[string]string{"c01": "confirm"}, false)
	comment := RenderComment(&Review{Completed: true, Verify: v, Findings: fs}, 0, 0)
	r.check("an injected reason is withheld from the comment", !strings.Contains(comment, "@maintainer") && !strings.Contains(comment, "attacker.example"))
	return r, nil
}

func gitInit(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	cmd := exec.Command("git", "-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "init", "-q", "-b", "main")
	if err := cmd.Run(); err != nil {
		return err
	}
	return exec.Command("git", "-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "empty").Run()
}

// Floors are the weekly run's bounds, set by the operator after four runs;
// zero means not yet set.
type Floors struct {
	MinDetections int
	MaxDecoys     int
	Set           bool
}

// Layer2Selftest sends a fresh corpus's change through the real Vornik
// review and requires: the review completes, the split key is confirmed,
// no decoy is confirmed; and, once floors are set, the bounds.
func Layer2Selftest(ctx context.Context, v *Vornik, prefix, gitleaks, workDir string, f Floors) (*SelftestReport, error) {
	r := &SelftestReport{Pass: true, Counts: map[string]int{}}
	c, err := NewCorpus(filepath.Join(workDir, "corpus"), gitleaks)
	if err != nil {
		return nil, err
	}
	r.Values = c.Values()
	acc, _ := ParseLedger("accounts.allow", strings.NewReader(CorpusAccounts))
	rv := RunReview(ctx, ReviewOptions{
		Scan:    Options{Repo: c.Dir, Base: c.Base, Head: c.Head, Gitleaks: gitleaks, WorkDir: filepath.Join(workDir, "scan"), Accounts: acc},
		Vornik:  v,
		Prefix:  prefix,
		HeadSHA: c.Head,
	})
	r.Layer2 = rv
	r.check("layer 2 completes", rv.Completed)
	for _, p := range c.Plants {
		if p.Layer != 2 && !p.Decoy {
			continue
		}
		hit := false
		for _, fd := range rv.Findings {
			if fd.Path == p.Path && abs(fd.Line-p.Line) <= 2 {
				hit = true
			}
		}
		if p.Decoy {
			if hit {
				r.Counts["decoys confirmed"]++
			}
			r.check("decoy not confirmed: "+p.Kind, !hit)
		} else {
			if hit {
				r.Counts["detections"]++
			}
			r.check("confirmed: "+p.Kind, hit)
		}
	}
	if f.Set {
		r.check(fmt.Sprintf("detections at or above the floor (%d)", f.MinDetections), r.Counts["detections"] >= f.MinDetections)
		r.check(fmt.Sprintf("decoys at or below the ceiling (%d)", f.MaxDecoys), r.Counts["decoys confirmed"] <= f.MaxDecoys)
	}
	return r, nil
}

// RenderSelftest writes a report: checks by name and counts, never a value.
func RenderSelftest(title string, r *SelftestReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## secretscan self-test: %s\n\n", title)
	verdict := "PASS"
	if !r.Pass {
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "**%s**: %d check(s), %d failed.\n\n| check | result |\n|---|---|\n", verdict, len(r.Checks), len(r.Failures))
	for _, c := range r.Checks {
		res := "ok"
		if !c.OK {
			res = "**FAIL**"
		}
		fmt.Fprintf(&b, "| %s | %s |\n", c.Name, res)
	}
	if len(r.Counts) > 0 {
		b.WriteString("\n")
		for _, k := range []string{"plants found", "plants missed", "decoys flagged", "detections", "decoys confirmed"} {
			if n, ok := r.Counts[k]; ok {
				fmt.Fprintf(&b, "- %s: %d\n", k, n)
			}
		}
	}
	if r.Layer2 != nil && !r.Layer2.Completed {
		fmt.Fprintf(&b, "\nLayer 2 did not complete: %s.\n", r.Layer2.Reason)
		writeFailures(&b, r.Layer2.Failures)
	}
	return b.String()
}

// Sweep searches files for every value, after planting one value in a
// control file of its own: a search that cannot find the control proves
// nothing. It returns the files that hold a value (the control excluded).
func Sweep(values []string, files []string, controlDir string) (hits []string, controlFound bool, err error) {
	if len(values) == 0 {
		return nil, false, fmt.Errorf("sweep: no values")
	}
	control := filepath.Join(controlDir, "sweep-control.txt")
	if err := os.WriteFile(control, []byte("control "+values[0]+"\n"), 0o600); err != nil {
		return nil, false, err
	}
	defer os.Remove(control)
	search := func(path string) (bool, error) {
		b, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return false, err
		}
		for _, v := range values {
			if v != "" && strings.Contains(string(b), v) {
				return true, nil
			}
		}
		return false, nil
	}
	if controlFound, err = search(control); err != nil {
		return nil, false, err
	}
	for _, f := range files {
		if ok, err := search(f); err != nil {
			return nil, controlFound, err
		} else if ok {
			hits = append(hits, f)
		}
	}
	return hits, controlFound, nil
}
