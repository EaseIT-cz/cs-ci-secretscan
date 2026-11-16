package secretscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
)

// ReviewOptions configure layer 2 and layer 3 for one change.
type ReviewOptions struct {
	Scan     Options // layer 1 over the change (Base..Head)
	Vornik   *Vornik
	Prefix   string // workflow id prefix, e.g. "claudecode--secretscan--"
	MaxDiff  int    // bytes per run (256 KiB)
	HeadSHA  string // the change's head commit, 40 hex
	Comments int    // claims shown at most (20)
	Chars    int    // model text shown at most (6000)
}

// Review is the outcome of layers 2 and 3, as reported.
type Review struct {
	Completed    bool
	Reason       string // why layer 2 did not complete
	Layer1       []Finding
	Files, Added int
	NotExamined  []string
	MaskRounds   int
	MaskedTokens int
	Claims       int
	Verify       VerifyResult
	Findings     []Finding2
	Dropped      map[string]int
	Triage       []Verdict
	HunterFailed []string
	// Failures names each workflow that did not complete and why, by error
	// class only (never content), so a failure explains itself.
	Failures map[string]string
}

// Verdict is a triage verdict on a layer 1 finding, after policy.
type Verdict struct {
	Fingerprint, Verdict, Reason string
}

type huntOutput struct {
	Status string `json:"status"`
	Claims []struct {
		Path   string  `json:"path"`
		Line   float64 `json:"line"`
		Class  string  `json:"class"`
		Reason string  `json:"reason"`
	} `json:"claims"`
}

type triageOutput struct {
	Status   string `json:"status"`
	Verdicts []struct {
		Fingerprint string `json:"fingerprint"`
		Verdict     string `json:"verdict"`
		Reason      string `json:"reason"`
	} `json:"verdicts"`
}

type adjudicateOutput struct {
	Status    string `json:"status"`
	Decisions []struct {
		ID       string `json:"id"`
		Decision string `json:"decision"`
	} `json:"decisions"`
	Triage []struct {
		Fingerprint string `json:"fingerprint"`
		Verdict     string `json:"verdict"`
		Reason      string `json:"reason"`
	} `json:"triage"`
}

// RunReview runs layers 2 and 3. It never returns an error for a layer 2
// failure: it reports it in the Review, so the caller can fail open.
func RunReview(ctx context.Context, o ReviewOptions) *Review {
	rv := &Review{Dropped: map[string]int{}, Failures: map[string]string{}}
	fail := func(format string, a ...any) *Review {
		rv.Completed = false
		rv.Reason = fmt.Sprintf(format, a...)
		return rv
	}
	if o.MaxDiff == 0 {
		o.MaxDiff = DefaultMaxDiff
	}
	if err := resolvePaths(&o.Scan); err != nil {
		return fail("a tool could not be found (%s)", firstLine(err.Error()))
	}
	diff, notExamined, err := changeDiff(o.Scan, o.MaxDiff)
	if err != nil {
		return fail("the diff could not be read")
	}
	rv.NotExamined = notExamined
	pd := ParseDiff(diff)
	rv.Files, rv.Added = pd.Files, pd.Added
	if pd.Added == 0 {
		rv.Completed = true
		return rv
	}
	res, err := Scan(o.Scan)
	if err != nil {
		return fail("layer 1 could not prove its coverage")
	}
	rv.Layer1 = res.Findings

	mo := MaskOptions{Diff: diff, Gitleaks: o.Scan.Gitleaks, Config: o.Scan.Config, WorkDir: o.Scan.WorkDir}
	m, err := Mask(mo)
	if errors.Is(err, ErrMaskNotHeld) {
		return fail("the mask did not hold; nothing was sent")
	}
	if err != nil {
		return fail("the mask could not run (a tool error); nothing was sent")
	}
	rv.MaskRounds, rv.MaskedTokens = m.Rounds, m.Masked
	masked := ParseDiff(m.Diff)
	layer1 := layer1Report(res.Findings, masked)
	// The report is masked text; prove it too before it leaves.
	if sp, err := rescan(layer1, o.Scan.Gitleaks, o.Scan.WorkDir, Checker{}, o.Scan.Config); err != nil || len(sp) > 0 {
		return fail("the layer 1 report did not mask clean; nothing was sent")
	}

	type result struct {
		out map[string]any
		err error
	}
	run := func(wf string, inputs map[string]any) result {
		task, err := o.Vornik.Delegate(ctx, o.Prefix+wf, inputs)
		if err != nil {
			return result{err: err}
		}
		out, err := o.Vornik.Wait(ctx, task)
		return result{out, err}
	}
	var wg sync.WaitGroup
	results := map[string]result{}
	var mu sync.Mutex
	for wf, in := range map[string]map[string]any{
		"hunt-a": {"diff": m.Diff, "head_sha": o.HeadSHA},
		"hunt-b": {"diff": m.Diff, "head_sha": o.HeadSHA},
		"triage": {"diff": m.Diff, "layer1": nonEmpty(layer1), "head_sha": o.HeadSHA},
	} {
		wg.Add(1)
		go func(wf string, in map[string]any) {
			defer wg.Done()
			r := run(wf, in)
			mu.Lock()
			results[wf] = r
			mu.Unlock()
		}(wf, in)
	}
	wg.Wait()

	var claims []Claim
	for wf, by := range map[string]string{"hunt-a": "a", "hunt-b": "b"} {
		r := results[wf]
		var h huntOutput
		switch {
		case r.err != nil:
			rv.Failures[wf] = firstLine(r.err.Error())
		case decode(r.out, &h) != nil:
			rv.Failures[wf] = "its output did not decode"
		case h.Status != "complete":
			rv.Failures[wf] = "it reported status " + h.Status
		}
		if rv.Failures[wf] != "" {
			rv.HunterFailed = append(rv.HunterFailed, wf)
			continue
		}
		for _, c := range h.Claims {
			claims = append(claims, Claim{Path: c.Path, Line: int(c.Line), Class: c.Class, Reason: c.Reason, By: by})
		}
	}
	sort.Strings(rv.HunterFailed)
	if len(rv.HunterFailed) == 2 {
		return fail("both hunters failed")
	}
	rv.Claims = len(claims)
	rv.Verify = Verify(claims, masked)

	var tri triageOutput
	triageOK := results["triage"].err == nil && decode(results["triage"].out, &tri) == nil
	if !triageOK {
		if e := results["triage"].err; e != nil {
			rv.Failures["triage"] = firstLine(e.Error())
		} else {
			rv.Failures["triage"] = "its output did not decode"
		}
	}
	bundle, err := json.Marshal(map[string]any{"claims": rv.Verify.Candidates, "triage": tri.Verdicts})
	if err != nil {
		return fail("the bundle could not be built")
	}
	if sp, err := rescan(string(bundle), o.Scan.Gitleaks, o.Scan.WorkDir, Checker{}, o.Scan.Config); err != nil || len(sp) > 0 {
		return fail("the bundle did not mask clean; nothing was sent")
	}
	decisions := map[string]string{}
	var adj adjudicateOutput
	if len(rv.Verify.Candidates) > 0 || len(tri.Verdicts) > 0 {
		r := run("adjudicate", map[string]any{"diff": m.Diff, "bundle": string(bundle), "head_sha": o.HeadSHA})
		if r.err != nil || decode(r.out, &adj) != nil {
			if r.err != nil {
				rv.Failures["adjudicate"] = firstLine(r.err.Error())
			}
			return fail("the adjudicator did not complete")
		}
		for _, d := range adj.Decisions {
			decisions[d.ID] = d.Decision
		}
	}
	rv.Findings, rv.Dropped = Adjudicate(rv.Verify.Candidates, decisions, len(rv.HunterFailed) > 0)
	rules := map[string]string{}
	for _, f := range res.Findings {
		rules[f.String()] = f.Rule
	}
	seen := map[string]bool{}
	for _, t := range adj.Triage {
		seen[t.Fingerprint] = true
		rv.Triage = append(rv.Triage, Verdict{t.Fingerprint, PolicyVerdict(rules[t.Fingerprint], t.Verdict), t.Reason})
	}
	if triageOK {
		for _, t := range tri.Verdicts {
			if !seen[t.Fingerprint] {
				rv.Triage = append(rv.Triage, Verdict{t.Fingerprint, PolicyVerdict(rules[t.Fingerprint], t.Verdict), t.Reason})
			}
		}
	}
	rv.Completed = true
	return rv
}

func nonEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(no findings)\n"
	}
	return s
}

// layer1Report is triage's input: one JSON line per layer 1 finding in the
// change, with its masked line as context; no gitleaks value field.
func layer1Report(fs []Finding, masked ParsedDiff) string {
	var b strings.Builder
	for _, f := range fs {
		l, ok := masked.Lines[Loc{f.Path, f.Line}]
		if !ok {
			continue // not in this change
		}
		rec, _ := json.Marshal(map[string]any{"fingerprint": f.String(), "path": f.Path, "line": f.Line, "rule": f.Rule, "context": l.Text})
		b.Write(rec)
		b.WriteByte('\n')
	}
	return b.String()
}

// changeDiff reads base..head, keeping whole files up to max bytes; the
// files that do not fit are returned as not examined.
func changeDiff(o Options, max int) (string, []string, error) {
	if o.Base == "" {
		return "", nil, errors.New("review: a base is required")
	}
	head := o.Head
	if head == "" {
		head = "HEAD"
	}
	cmd := exec.Command("git", "-C", o.Repo, "diff", "--no-textconv", "--no-ext-diff", "--no-color", "-U3", o.Base+"..."+head)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	out, err := cmd.Output()
	if err != nil {
		return "", nil, err
	}
	var kept strings.Builder
	var not []string
	files := splitFiles(string(out))
	// Code first, documentation last: when the cap is reached, what is left
	// unreviewed is prose, which layer 1 still scans.
	sort.SliceStable(files, func(i, j int) bool { return !isDoc(filePath(files[i])) && isDoc(filePath(files[j])) })
	for _, file := range files {
		if kept.Len()+len(file) > max {
			not = append(not, filePath(file))
			continue
		}
		kept.WriteString(file)
	}
	return kept.String(), not, nil
}

// DefaultMaxDiff is what one review sends at most. A 77 KB diff exceeded
// what a hunter could read within Vornik's 30-iteration tool limit
// (measured on a real pull request, 2026-11-16).
const DefaultMaxDiff = 24 << 10

func isDoc(p string) bool {
	return strings.HasSuffix(p, ".md") || strings.HasSuffix(p, ".txt") || strings.HasPrefix(p, "docs/")
}

func splitFiles(d string) []string {
	var out []string
	for _, part := range strings.SplitAfter(d, "\n") {
		if strings.HasPrefix(part, "diff --git ") || len(out) == 0 {
			out = append(out, part)
			continue
		}
		out[len(out)-1] += part
	}
	return out
}

func filePath(file string) string {
	for _, l := range strings.Split(file, "\n") {
		if strings.HasPrefix(l, "+++ b/") {
			return strings.TrimPrefix(l, "+++ b/")
		}
	}
	first, _, _ := strings.Cut(file, "\n")
	return strings.TrimPrefix(first, "diff --git ")
}

// CommentMarker finds this tool's comment on a pull request.
const CommentMarker = "<!-- secretscan:review -->"

// RenderComment writes the pull-request comment: what was examined, what
// each layer found, and what was not examined. The only model text is
// each reason, already filtered by layer 3, in a table cell.
func RenderComment(rv *Review, maxClaims, maxChars int) string {
	if maxClaims == 0 {
		maxClaims = 20
	}
	if maxChars == 0 {
		maxChars = 6000
	}
	var b strings.Builder
	b.WriteString(CommentMarker + "\n### Secret scan: Vornik review (comment only)\n\n")
	if !rv.Completed {
		fmt.Fprintf(&b, "**Layer 2 did not complete:** %s. Layer 1 (the `secret-scan` job) is unaffected.\n", rv.Reason)
		writeFailures(&b, rv.Failures)
		return b.String()
	}
	fmt.Fprintf(&b, "Examined %d file(s), %d added line(s); masked %d value(s) in %d round(s) before sending. ", rv.Files, rv.Added, rv.MaskedTokens, rv.MaskRounds)
	fmt.Fprintf(&b, "Hunter claims: %d; kept after the deterministic check: %d; confirmed by the adjudicator: %d.\n\n", rv.Claims, len(rv.Verify.Candidates), len(rv.Findings))
	if len(rv.HunterFailed) > 0 {
		fmt.Fprintf(&b, "Did not complete: %s, so no finding is rated high.\n", strings.Join(rv.HunterFailed, ", "))
		writeFailures(&b, rv.Failures)
		b.WriteString("\n")
	}
	if len(rv.Findings) == 0 {
		b.WriteString("**No finding from the model review.**\n\n")
	} else {
		b.WriteString("| confidence | where | class | found by | reason |\n|---|---|---|---|---|\n")
		chars, shown := 0, 0
		for _, f := range rv.Findings {
			reason := strings.Join(f.Reasons, "; ")
			if shown >= maxClaims || chars+len(reason) > maxChars {
				continue
			}
			shown++
			chars += len(reason)
			fmt.Fprintf(&b, "| %s | %s:%d | %s | %s | %s |\n", f.Confidence, codeSpan(f.Path), f.Line, f.Class, f.FoundBy, reason)
		}
		if shown < len(rv.Findings) {
			fmt.Fprintf(&b, "\n%d more finding(s) not shown (caps: %d claims, %d characters).\n", len(rv.Findings)-shown, maxClaims, maxChars)
		}
		b.WriteString("\n")
	}
	if len(rv.Triage) > 0 {
		b.WriteString("**Triage of layer 1's findings:**\n\n| finding | verdict |\n|---|---|\n")
		for _, t := range rv.Triage {
			fmt.Fprintf(&b, "| %s | %s |\n", codeSpan(t.Fingerprint), t.Verdict)
		}
		b.WriteString("\n")
	}
	if len(rv.NotExamined) > 0 {
		fmt.Fprintf(&b, "Not reviewed by layer 2 (over its %d KiB cap; layer 1 scanned them): %d file(s).\n", DefaultMaxDiff>>10, len(rv.NotExamined))
	}
	var drops []string
	for k, n := range rv.Verify.Dropped {
		drops = append(drops, fmt.Sprintf("%s %d", k, n))
	}
	for k, n := range rv.Dropped {
		drops = append(drops, fmt.Sprintf("%s %d", k, n))
	}
	sort.Strings(drops)
	if len(drops) > 0 {
		fmt.Fprintf(&b, "Dropped claims: %s.\n", strings.Join(drops, ", "))
	}
	return b.String()
}

func writeFailures(b *strings.Builder, f map[string]string) {
	var keys []string
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r := strings.NewReplacer("`", "'", "|", "/", "\n", " ", "<", "(", ">", ")").Replace(f[k])
		fmt.Fprintf(b, "- %s: %s\n", k, r)
	}
}

func codeSpan(s string) string {
	s = strings.NewReplacer("`", "'", "|", "\\|", "\n", " ").Replace(s)
	return "`" + s + "`"
}
