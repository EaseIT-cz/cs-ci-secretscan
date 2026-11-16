package secretscan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// DiffLine is one line of a unified diff, by its new-file position.
type DiffLine struct {
	Text  string // without the leading "+" or " "
	Added bool
}

// ParsedDiff indexes a unified diff's lines by path and new-file line.
type ParsedDiff struct {
	Lines map[Loc]DiffLine
	Files int // files with a new side
	Added int // added lines
}

var hunkHead = regexp.MustCompile(`^@@ -[0-9,]+ \+([0-9]+)`)

// ParseDiff reads a unified diff (git diff -U<n>).
func ParseDiff(d string) ParsedDiff {
	pd := ParsedDiff{Lines: map[Loc]DiffLine{}}
	path, line := "", 0
	for _, l := range strings.Split(d, "\n") {
		switch {
		case strings.HasPrefix(l, "diff --git "):
			path = ""
		case strings.HasPrefix(l, "+++ "):
			path = strings.TrimPrefix(strings.TrimPrefix(l, "+++ "), "b/")
			if path == "/dev/null" {
				path = ""
			} else {
				pd.Files++
			}
		case strings.HasPrefix(l, "--- "):
		case strings.HasPrefix(l, "@@ "):
			if m := hunkHead.FindStringSubmatch(l); m != nil {
				fmt.Sscan(m[1], &line)
			}
		case path == "" || line == 0:
		case strings.HasPrefix(l, "+"):
			pd.Lines[Loc{path, line}] = DiffLine{Text: l[1:], Added: true}
			pd.Added++
			line++
		case strings.HasPrefix(l, " "):
			pd.Lines[Loc{path, line}] = DiffLine{Text: l[1:]}
			line++
		}
	}
	return pd
}

// MaskOptions configure Mask.
type MaskOptions struct {
	Diff     string
	Gitleaks string
	Config   string // the gitleaks config; empty uses gitleaks' defaults
	WorkDir  string
	Checker  Checker
}

// MaskResult is the masked diff and what masking it took.
type MaskResult struct {
	Diff   string
	Rounds int // rescans until one found nothing
	Masked int // tokens replaced
}

// maxRounds bounds the mask: each round masks what a rescan found, and the
// last rescan must find nothing.
const maxRounds = 5

// Mask replaces every value gitleaks or the structural checks find in the
// diff, and every 12-digit account id, with [REDACTED:<rule>], then rescans
// until a rescan finds nothing: that clean rescan is the proof the mask
// held. It anchors on lines and tokens, never on gitleaks' exact columns,
// which are one late on every line after the first (docs/design.md §2).
// The line count is unchanged, so line numbers still match the original.
func Mask(o MaskOptions) (*MaskResult, error) {
	if o.Gitleaks == "" || o.WorkDir == "" {
		return nil, errors.New("mask: Gitleaks and WorkDir are required")
	}
	lines := strings.Split(o.Diff, "\n")
	res := &MaskResult{}
	for round := 1; round <= maxRounds; round++ {
		spans, err := rescan(strings.Join(lines, "\n"), o.Gitleaks, o.WorkDir, o.Checker, o.Config)
		if err != nil {
			return nil, err
		}
		res.Rounds = round
		if len(spans) == 0 {
			res.Diff = strings.Join(lines, "\n")
			return res, nil
		}
		for _, sp := range spans {
			i := sp.line - 1
			if i < 0 || i >= len(lines) {
				continue
			}
			masked := maskSpan(lines[i], sp.start, sp.end, sp.rule)
			if masked != lines[i] {
				res.Masked++
				lines[i] = masked
			} else {
				// The span hit no token it could replace: mask the line's
				// content whole rather than send it.
				lines[i] = keepPrefix(lines[i]) + "[REDACTED:" + sp.rule + "]"
				res.Masked++
			}
		}
	}
	return nil, fmt.Errorf("mask: still finding values after %d rounds; the mask did not hold", maxRounds)
}

// span is a finding's place in the scanned stream: 1-based line and columns.
type span struct {
	line, start, end int
	rule             string
}

var (
	accountRun = regexp.MustCompile(`(^|[^A-Za-z0-9])([0-9](?:[ -]?[0-9]){11})([^A-Za-z0-9]|$)`)
	alreadyRed = regexp.MustCompile(`\[REDACTED:[a-z0-9-]+\]`)
)

// rescan finds every value to mask in text: gitleaks over it as a stream,
// the structural line checks, and every 12-digit run, plain or split by
// dashes or spaces (the mask is wider than layer 1's account-id rule).
func rescan(text, gitleaks, workDir string, c Checker, config string) ([]span, error) {
	fs, err := runGitleaksStdin(gitleaks, config, workDir, []byte(text))
	if err != nil {
		return nil, err
	}
	var out []span
	for _, f := range fs {
		out = append(out, span{f.StartLine, f.StartColumn, f.EndColumn, f.RuleID})
	}
	for i, l := range strings.Split(text, "\n") {
		clean := alreadyRed.ReplaceAllString(l, "")
		for _, loc := range urlPassword.FindAllStringIndex(clean, -1) {
			out = append(out, span{i + 1, loc[0] + 1, loc[1], RuleURLPassword})
		}
		for _, loc := range pemKey.FindAllStringIndex(clean, -1) {
			out = append(out, span{i + 1, loc[0] + 1, loc[1], RulePEMKey})
		}
		for _, m := range accountRun.FindAllStringSubmatchIndex(clean, -1) {
			out = append(out, span{i + 1, m[4] + 1, m[5], RuleAccountID})
		}
	}
	_ = c // the structural rules above need no ledger: the mask is wider
	return out, nil
}

// maskSpan replaces every token the 1-based column span, widened by one
// character each side, overlaps. Tokens split at whitespace, quotes, "="
// and backticks. A diff line's leading "+", "-" or " " is kept.
func maskSpan(line string, start, end int, rule string) string {
	lo, hi := start-2, end+1 // 0-based, widened by one each side
	if lo < 0 {
		lo = 0
	}
	if hi > len(line) {
		hi = len(line)
	}
	first := 0
	if len(line) > 0 && strings.ContainsRune("+- ", rune(line[0])) {
		first = 1
	}
	var b strings.Builder
	b.WriteString(line[:first])
	i := first
	for i < len(line) {
		if isSep(line[i]) {
			b.WriteByte(line[i])
			i++
			continue
		}
		j := i
		for j < len(line) && !isSep(line[j]) {
			j++
		}
		tok := line[i:j]
		if i < hi && j > lo && !alreadyRed.MatchString(tok) {
			b.WriteString("[REDACTED:" + rule + "]")
		} else {
			b.WriteString(tok)
		}
		i = j
	}
	return b.String()
}

func isSep(c byte) bool {
	return c == ' ' || c == '\t' || c == '"' || c == '\'' || c == '`' || c == '='
}

func keepPrefix(l string) string {
	if len(l) > 0 && strings.ContainsRune("+- ", rune(l[0])) {
		return l[:1]
	}
	return ""
}

// glSpan is a gitleaks stdin finding's position; values are never read.
type glSpan struct {
	StartLine, StartColumn, EndColumn int
	RuleID                            string
}

// runGitleaksStdin scans data as a stream at debug level with --redact.
func runGitleaksStdin(gitleaks, config, workDir string, data []byte) ([]glSpan, error) {
	report, err := os.CreateTemp(workDir, "mask-*.json")
	if err != nil {
		return nil, err
	}
	report.Close()
	defer os.Remove(report.Name())
	args := []string{"stdin", "--no-banner", "--redact", "--log-level", "debug",
		"--report-format", "json", "--report-path", report.Name()}
	if config != "" {
		args = append(args, "--config", config)
	}
	cmd := exec.Command(gitleaks, args...)
	cmd.Dir = workDir
	cmd.Stdin = bytes.NewReader(data)
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			return nil, fmt.Errorf("gitleaks stdin: %w", err)
		}
	}
	raw, err := os.ReadFile(report.Name())
	if err != nil {
		return nil, err
	}
	var fs []glSpan
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &fs); err != nil {
			return nil, fmt.Errorf("gitleaks stdin: report unreadable: %w", err)
		}
	}
	return fs, nil
}

// ReadDiffFile reads a diff written by git diff, for the command.
func ReadDiffFile(path string) (string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer f.Close()
	var b strings.Builder
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for s.Scan() {
		b.WriteString(s.Text())
		b.WriteByte('\n')
	}
	return b.String(), s.Err()
}
