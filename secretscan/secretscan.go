// Package secretscan holds the deterministic checks of a layered secret
// scan (docs/design.md): the structural checks gitleaks lacks, the ledgers
// that exempt a named value or path with its reason, the tree scan's byte
// balance, and the rules for gitleaks' inline allow markers.
//
// A Finding names a path, a line and a rule, never a value, so a report
// built from findings cannot carry the secret it reports.
package secretscan

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The rules, as they appear in reports.
const (
	RuleKeyFile               = "key-file"
	RuleCachePath             = "cache-path"
	RulePEMKey                = "pem-private-key"
	RuleURLPassword           = "url-password"
	RuleAccountID             = "account-id"
	RuleMarkerNoReason        = "marker-without-reason"
	RuleMarkerSilencesNothing = "marker-silences-nothing"
)

// Finding is one layer 1 finding. It never holds the matched text.
type Finding struct {
	Path string
	Line int
	Rule string
}

func (f Finding) String() string {
	if f.Line == 0 {
		return f.Path + " " + f.Rule
	}
	return f.Path + ":" + strconv.Itoa(f.Line) + " " + f.Rule
}

// Ledger is an allowlist file: one "<value>\t<reason>" per line, blank
// lines and "#" comments allowed. Every entry has a reason, so an
// exemption is never unexplained.
type Ledger struct {
	reasons map[string]string
}

// ParseLedger reads a ledger. A line without exactly one tab, an empty
// value or reason, or a duplicate value is an error naming the line.
func ParseLedger(name string, r io.Reader) (*Ledger, error) {
	l := &Ledger{reasons: map[string]string{}}
	s := bufio.NewScanner(r)
	n := 0
	for s.Scan() {
		n++
		line := s.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s:%d: want <value><TAB><reason>", name, n)
		}
		value, reason := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if value == "" || reason == "" {
			return nil, fmt.Errorf("%s:%d: empty value or reason", name, n)
		}
		if _, dup := l.reasons[value]; dup {
			return nil, fmt.Errorf("%s:%d: %q listed twice", name, n, value)
		}
		l.reasons[value] = reason
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return l, nil
}

// Has reports whether the ledger lists value. A nil ledger lists nothing.
func (l *Ledger) Has(value string) bool {
	if l == nil {
		return false
	}
	_, ok := l.reasons[value]
	return ok
}

// Len is the number of entries.
func (l *Ledger) Len() int {
	if l == nil {
		return 0
	}
	return len(l.reasons)
}

// Checker runs the structural checks. Names exempts key-file paths,
// Accounts exempts 12-digit values, and AccountVars holds the repository's
// own account ids, which are a finding wherever they appear.
type Checker struct {
	Names       *Ledger
	Accounts    *Ledger
	AccountVars []string
}

// CheckPath checks one tracked path's name. A path under a cache the
// gitleaks config allowlists is reported as that alone: gitleaks never
// scans it, so it must not be committed at all.
func (c Checker) CheckPath(p string) []Finding {
	if isCachePath(p) {
		return []Finding{{Path: p, Rule: RuleCachePath}}
	}
	if isKeyFileName(p) && !inTestdata(p) && !c.Names.Has(p) {
		return []Finding{{Path: p, Rule: RuleKeyFile}}
	}
	return nil
}

func isCachePath(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".tools" || seg == ".terraform" {
			return true
		}
	}
	return path.Base(p) == "errored_test.tfstate"
}

func isKeyFileName(p string) bool {
	base := path.Base(p)
	switch ext := path.Ext(base); ext {
	case ".pem", ".key", ".tfvars":
		return true
	}
	return strings.HasPrefix(base, "id_rsa") || strings.HasPrefix(base, "id_ed25519") ||
		strings.Contains(base, ".tfstate") || base == ".env" || strings.HasPrefix(base, ".env.")
}

func inTestdata(p string) bool {
	return strings.HasPrefix(p, "testdata/") || strings.Contains(p, "/testdata/")
}

var (
	pemKey = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`)
	// A URL whose authority carries user:password@ ; the user and password
	// may not hold "/", whitespace, quotes or "@", so a path's "@" is not one.
	urlPassword = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@'"]+:[^/\s@'"]+@`)
)

// CheckLine checks one added line. It returns at most one finding per
// rule and position; the caller adds the path and line.
func (c Checker) CheckLine(line string) []Finding {
	var out []Finding
	if pemKey.MatchString(line) {
		out = append(out, Finding{Rule: RulePEMKey})
	}
	if urlPassword.MatchString(line) {
		out = append(out, Finding{Rule: RuleURLPassword})
	}
	for _, n := range twelveDigitRuns(line) {
		if c.isAccountVar(n) || !c.Accounts.Has(n) {
			out = append(out, Finding{Rule: RuleAccountID})
		}
	}
	return out
}

func (c Checker) isAccountVar(n string) bool {
	for _, v := range c.AccountVars {
		if v == n {
			return true
		}
	}
	return false
}

// twelveDigitRuns returns every maximal run of exactly 12 decimal digits.
func twelveDigitRuns(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		if s[i] < '0' || s[i] > '9' {
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j-i == 12 {
			out = append(out, s[i:j])
		}
		i = j
	}
	return out
}

// ScanLog is what a gitleaks run at --log-level debug reports about its
// own coverage: the files it skipped, by name, and the bytes it scanned.
type ScanLog struct {
	ScannedBytes int64
	Skipped      []string
}

var (
	ansi     = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	skipLine = regexp.MustCompile(`skipping (?:file|empty file)[^=]*path=(\S+)`)
	bytesRe  = regexp.MustCompile(`scanned ~([0-9]+) bytes`)
)

// ParseScanLog reads gitleaks' debug log. A log without the scanned-bytes
// line is an error: it is never read as 0 bytes, clean.
func ParseScanLog(r io.Reader) (ScanLog, error) {
	var l ScanLog
	seen := map[string]bool{}
	found := false
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		line := ansi.ReplaceAllString(s.Text(), "")
		if m := skipLine.FindStringSubmatch(line); m != nil && !seen[m[1]] {
			seen[m[1]] = true
			l.Skipped = append(l.Skipped, m[1])
		}
		if m := bytesRe.FindStringSubmatch(line); m != nil {
			n, err := strconv.ParseInt(m[1], 10, 64)
			if err != nil {
				return l, fmt.Errorf("scan log: bytes %q: %w", m[1], err)
			}
			l.ScannedBytes, found = n, true
		}
	}
	if err := s.Err(); err != nil {
		return l, fmt.Errorf("scan log: %w", err)
	}
	if !found {
		return l, fmt.Errorf("scan log: no \"scanned ~N bytes\" line; the scan's coverage is unknown")
	}
	return l, nil
}

// Balance is the tree scan's denominator, as checked.
type Balance struct {
	TrackedFiles, SkippedFiles int
	TrackedBytes, SkippedBytes int64
	ScannedBytes               int64
}

// CheckBalance requires the tracked bytes, less the bytes of the files
// gitleaks names as skipped, to equal the bytes gitleaks scanned, exactly.
// A difference means a file was skipped without being named, or the two
// disagree about what was read; either way "clean" would be unproven.
// sizes maps every tracked path to its size.
func CheckBalance(sizes map[string]int64, l ScanLog) (Balance, error) {
	b := Balance{TrackedFiles: len(sizes), ScannedBytes: l.ScannedBytes}
	if len(sizes) == 0 {
		return b, fmt.Errorf("balance: no tracked files; an empty tree is never clean")
	}
	for _, sz := range sizes {
		b.TrackedBytes += sz
	}
	for _, p := range l.Skipped {
		sz, ok := sizes[p]
		if !ok {
			return b, fmt.Errorf("balance: gitleaks skipped %s, which is not a tracked file", p)
		}
		b.SkippedFiles++
		b.SkippedBytes += sz
	}
	if want := b.TrackedBytes - b.SkippedBytes; want != l.ScannedBytes {
		return b, fmt.Errorf("balance: %d tracked bytes less %d skipped is %d, but gitleaks scanned %d",
			b.TrackedBytes, b.SkippedBytes, want, l.ScannedBytes)
	}
	return b, nil
}

// Loc is a path and line.
type Loc struct {
	Path string
	Line int
}

// marker is gitleaks' inline allow marker, written in two parts so this
// file holds none for a scan of it to read as one.
const marker = "gitleaks" + ":allow"

// CheckMarkers checks each line holding an inline allow marker. lines
// maps each such line to its text; fired holds the lines a scan with
// --ignore-gitleaks-allow reported. A marker must name its reason, and
// must sit on a line that would otherwise be a finding: one that silences
// nothing is a standing permission for whatever a later edit puts there.
func CheckMarkers(lines map[Loc]string, fired map[Loc]bool) []Finding {
	var out []Finding
	for loc, text := range lines {
		i := strings.Index(text, marker)
		if i < 0 {
			continue
		}
		switch {
		case strings.TrimSpace(text[i+len(marker):]) == "":
			out = append(out, Finding{Path: loc.Path, Line: loc.Line, Rule: RuleMarkerNoReason})
		case !fired[loc]:
			out = append(out, Finding{Path: loc.Path, Line: loc.Line, Rule: RuleMarkerSilencesNothing})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Line < out[j].Line
	})
	return out
}
