package secretscan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Pseudo-paths for findings outside a file. A path or message is reported
// by position only, because its text may be the secret.
const (
	CommitMessagesName = "(commit message)"
	PathListName       = "(paths)"
)

// Options configure one layer 1 scan (docs/design.md §3).
type Options struct {
	Repo     string // the git repository; its index is the tree scanned
	Base     string // the range's base; empty skips the range scan
	Head     string // the range's head and the history's tip; empty means HEAD
	Gitleaks string // the gitleaks binary
	Config   string // the gitleaks config; empty writes a defaults-only one
	WorkDir  string // an empty scratch directory

	Accounts    *Ledger  // 12-digit values that are not findings
	Names       *Ledger  // key-file paths that are not findings
	Skip        *Ledger  // skipped paths exempt from the stdin rescan
	AccountVars []string // the consumer's own account ids
}

// Result is a scan's findings and its denominators: what was examined, so
// "no findings" never stands for "not looked at".
type Result struct {
	Findings        []Finding
	Tree            Balance
	StdinRescanned  []string // skipped files scanned again through stdin
	SkipExempt      []string // skipped files the skip ledger exempts
	RangeCommits    int      // commits of the range that add a line
	HistoryCommits  int      // commits of the history that add a line
	MessageBytes    int64
	PathCount       int
	StructuralLines int
	Markers         int
}

// Scan runs layer 1. An error means the scan's coverage is unproven; it is
// never a clean result.
func Scan(o Options) (*Result, error) {
	s := &scanner{o: o, res: &Result{}}
	if err := s.setup(); err != nil {
		return nil, err
	}
	steps := []func() error{s.tree, s.history, s.rangeScan, s.messagesAndPaths, s.structural, s.markers}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, err
		}
	}
	s.res.Findings = dedupe(s.res.Findings)
	return s.res, nil
}

type scanner struct {
	o       Options
	res     *Result
	treeDir string // the index export
	hooks   string // an empty hooks directory
	config  string
	head    string
	paths   []string // tracked paths
	markLns map[Loc]string
	// structFired holds the tree lines where a structural rule fired but a
	// reasoned marker exempted it; the marker check counts them as fired.
	structFired map[Loc]bool
}

func (s *scanner) setup() error {
	if s.o.Gitleaks == "" || s.o.Repo == "" || s.o.WorkDir == "" {
		return errors.New("scan: Repo, Gitleaks and WorkDir are required")
	}
	if err := resolvePaths(&s.o); err != nil {
		return err
	}
	s.treeDir = filepath.Join(s.o.WorkDir, "tree")
	s.hooks = filepath.Join(s.o.WorkDir, "no-hooks")
	for _, d := range []string{s.treeDir, s.hooks} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	s.config = s.o.Config
	if s.config == "" {
		s.config = filepath.Join(s.o.WorkDir, "default.gitleaks.toml")
		if err := os.WriteFile(s.config, []byte("[extend]\nuseDefault = true\n"), 0o600); err != nil {
			return err
		}
	}
	s.head = s.o.Head
	if s.head == "" {
		s.head = "HEAD"
	}
	// A shallow clone hides history from git and gitleaks alike, so their
	// commit counts agree and prove nothing; refuse it outright.
	out, err := s.git(nil, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != "false" {
		return errors.New("scan: the clone is shallow; fetch the full history (fetch-depth: 0)")
	}
	return nil
}

// resolvePaths makes every path in o absolute, and looks a bare gitleaks
// name up on PATH: the commands run in different directories. Scan and
// RunReview both call it, so the mask never sees a relative path (found at
// e2e-lane: the review's mask ran a relative gitleaks from its scratch
// directory).
func resolvePaths(o *Options) error {
	var err error
	if o.Gitleaks, err = toolPath(o.Gitleaks); err != nil {
		return err
	}
	for _, p := range []*string{&o.Repo, &o.WorkDir, &o.Config} {
		if *p == "" {
			continue
		}
		if *p, err = filepath.Abs(*p); err != nil {
			return err
		}
	}
	return nil
}

// toolPath resolves a tool reference to an absolute path: a path is made
// absolute, a bare name is looked up on PATH. Every gitleaks run calls it,
// because the runs happen in other directories (a scratch export, a corpus,
// the repository): a relative path broke the review's mask, then the
// self-test's corpus, before this was made the one place (three bugs of
// one class, found at e2e-lane).
func toolPath(p string) (string, error) {
	var (
		abs string
		err error
	)
	if strings.ContainsRune(p, filepath.Separator) {
		abs, err = filepath.Abs(p)
	} else {
		abs, err = exec.LookPath(p)
	}
	if err != nil {
		return "", fmt.Errorf("gitleaks: %w", err)
	}
	return abs, nil
}

// git runs git with no system or global config and no hooks, so nothing
// the repository's history holds can configure or run a program.
func (s *scanner) git(stdin []byte, args ...string) ([]byte, error) {
	full := append([]string{"-c", "core.hooksPath=" + s.hooks, "-C", s.o.Repo}, args...)
	cmd := exec.Command("git", full...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_TERMINAL_PROMPT=0")
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// glFinding is the part of a gitleaks report finding the scan reads. The
// report is written with --redact; the value fields are never read.
type glFinding struct {
	File      string
	StartLine int
	EndLine   int
	RuleID    string
	Commit    string
}

// gitleaks runs one gitleaks command at debug level (never trace, which
// prints discarded candidate values) and returns its log and findings.
func (s *scanner) gitleaks(dir string, stdin []byte, args ...string) (string, []glFinding, error) {
	report, err := os.CreateTemp(s.o.WorkDir, "report-*.json")
	if err != nil {
		return "", nil, err
	}
	report.Close()
	defer os.Remove(report.Name())
	full := append(args, "--config", s.config, "--no-banner", "--redact", "--log-level", "debug",
		"--report-format", "json", "--report-path", report.Name())
	bin, err := toolPath(s.o.Gitleaks)
	if err != nil {
		return "", nil, err
	}
	cmd := exec.Command(bin, full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	runErr := cmd.Run()
	code := 0
	if runErr != nil {
		var ee *exec.ExitError
		if !errors.As(runErr, &ee) {
			return "", nil, fmt.Errorf("gitleaks %s: %w", args[0], runErr)
		}
		code = ee.ExitCode()
	}
	if code != 0 && code != 1 {
		return "", nil, fmt.Errorf("gitleaks %s: exit %d", args[0], code)
	}
	raw, err := os.ReadFile(report.Name())
	if err != nil {
		return "", nil, fmt.Errorf("gitleaks %s: report: %w", args[0], err)
	}
	var fs []glFinding
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &fs); err != nil {
			return "", nil, fmt.Errorf("gitleaks %s: report unreadable: %w", args[0], err)
		}
	}
	if code == 1 && len(fs) == 0 {
		return "", nil, fmt.Errorf("gitleaks %s: exit 1 with an empty report", args[0])
	}
	return log.String(), fs, nil
}

// tree exports the index, scans it, balances its bytes, and scans every
// skipped file again through stdin.
func (s *scanner) tree() error {
	if _, err := s.git(nil, "checkout-index", "-a", "-f", "--prefix="+s.treeDir+"/"); err != nil {
		return err
	}
	out, err := s.git(nil, "ls-files", "-z")
	if err != nil {
		return err
	}
	sizes := map[string]int64{}
	for _, p := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if p == "" {
			continue
		}
		fi, err := os.Lstat(filepath.Join(s.treeDir, p))
		if err != nil {
			return fmt.Errorf("tree: %s: %w", p, err)
		}
		s.paths = append(s.paths, p)
		if fi.Mode().IsRegular() {
			sizes[p] = fi.Size()
		} else {
			sizes[p] = 0 // a symlink or submodule: no content of its own
		}
	}
	log, fs, err := s.gitleaks(s.treeDir, nil, "dir", ".")
	if err != nil {
		return err
	}
	for _, f := range fs {
		s.add(Finding{Path: f.File, Line: f.StartLine, Rule: f.RuleID})
	}
	sl, err := ParseScanLog(strings.NewReader(log))
	if err != nil {
		return err
	}
	if s.res.Tree, err = CheckBalance(sizes, sl); err != nil {
		return err
	}
	for _, p := range sl.Skipped {
		if s.o.Skip.Has(p) {
			s.res.SkipExempt = append(s.res.SkipExempt, p)
			if path.Base(p) == "go.sum" {
				if err := s.checkGoSum(p); err != nil {
					return err
				}
			}
			continue
		}
		if sizes[p] == 0 {
			continue
		}
		content, err := os.ReadFile(filepath.Join(s.treeDir, p))
		if err != nil {
			return err
		}
		_, fs, err := s.gitleaks(s.o.WorkDir, content, "stdin")
		if err != nil {
			return err
		}
		for _, f := range fs {
			s.add(Finding{Path: p, Line: f.StartLine, Rule: f.RuleID})
		}
		s.res.StdinRescanned = append(s.res.StdinRescanned, p)
	}
	return nil
}

// goSumLine is go.sum's grammar: module, version (optionally /go.mod),
// and an h1: hash of 44 base64 characters.
var goSumLine = regexp.MustCompile(`^\S+ v\S+ h1:[A-Za-z0-9+/]{43}=$`)

// checkGoSum reads an exempt go.sum line by line: an exemption from the
// stdin rescan is not a blind spot, because any line outside go.sum's
// grammar is a finding.
func (s *scanner) checkGoSum(p string) error {
	content, err := os.ReadFile(filepath.Join(s.treeDir, p))
	if err != nil {
		return err
	}
	for i, l := range strings.Split(strings.TrimRight(string(content), "\n"), "\n") {
		if l != "" && !goSumLine.MatchString(l) {
			s.add(Finding{Path: p, Line: i + 1, Rule: RuleGoSumFormat})
		}
	}
	return nil
}

var commitsScanned = regexp.MustCompile(`([0-9]+) commits scanned`)

// gitScan runs gitleaks over a revision range and checks its commit count
// against git's: the non-merge commits that add a line.
func (s *scanner) gitScan(revs string) (int, error) {
	log, fs, err := s.gitleaks(s.o.Repo, nil, "git", ".", "--log-opts="+revs)
	if err != nil {
		return 0, err
	}
	for _, f := range fs {
		s.add(Finding{Path: f.File, Line: f.StartLine, Rule: f.RuleID})
	}
	want, err := s.commitsWithAdditions(revs)
	if err != nil {
		return 0, err
	}
	got := 0
	if m := commitsScanned.FindStringSubmatch(stripANSI(log)); m != nil {
		got, _ = strconv.Atoi(m[1])
	} else if want > 0 {
		return 0, fmt.Errorf("gitleaks git %s: no commit count in its log", revs)
	}
	if got != want {
		return 0, fmt.Errorf("gitleaks git %s: scanned %d commits, git has %d that add a line (is the clone shallow?)", revs, got, want)
	}
	return want, nil
}

func (s *scanner) commitsWithAdditions(revs string) (int, error) {
	out, err := s.git(nil, "log", "--no-merges", "--format=C %H", "--numstat", revs)
	if err != nil {
		return 0, err
	}
	n, adds, in := 0, false, false
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "C ") {
			if in && adds {
				n++
			}
			in, adds = true, false
			continue
		}
		if f := strings.Fields(line); len(f) == 3 && (f[0] == "-" || f[0] != "0") {
			adds = true
		}
	}
	if in && adds {
		n++
	}
	return n, nil
}

func (s *scanner) history() error {
	n, err := s.gitScan(s.head)
	s.res.HistoryCommits = n
	return err
}

func (s *scanner) rangeScan() error {
	if s.o.Base == "" {
		return nil
	}
	n, err := s.gitScan(s.o.Base + ".." + s.head)
	s.res.RangeCommits = n
	return err
}

// messagesAndPaths scans every commit message and every path in the
// history, which gitleaks git does not read.
func (s *scanner) messagesAndPaths() error {
	out, err := s.git(nil, "log", "--format=%x00%H%n%B", s.head)
	if err != nil {
		return err
	}
	var stream bytes.Buffer
	var owner []string // the commit of each stream line
	for _, rec := range strings.Split(string(out), "\x00") {
		if rec == "" {
			continue
		}
		sha, msg, _ := strings.Cut(rec, "\n")
		for _, l := range strings.Split(msg, "\n") {
			stream.WriteString(l + "\n")
			owner = append(owner, sha)
		}
	}
	s.res.MessageBytes = int64(stream.Len())
	if stream.Len() > 0 {
		_, fs, err := s.gitleaks(s.o.WorkDir, stream.Bytes(), "stdin")
		if err != nil {
			return err
		}
		for _, f := range fs {
			who := "?"
			if f.StartLine >= 1 && f.StartLine <= len(owner) {
				who = owner[f.StartLine-1][:12]
			}
			s.add(Finding{Path: CommitMessagesName + " " + who, Rule: f.RuleID})
		}
	}
	out, err = s.git(nil, "log", "--format=", "--name-only", s.head)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var list []string
	for _, p := range append(strings.Split(string(out), "\n"), s.paths...) {
		if p != "" && !seen[p] {
			seen[p] = true
			list = append(list, p)
		}
	}
	sort.Strings(list)
	s.res.PathCount = len(list)
	if len(list) > 0 {
		_, fs, err := s.gitleaks(s.o.WorkDir, []byte(strings.Join(list, "\n")+"\n"), "stdin")
		if err != nil {
			return err
		}
		for _, f := range fs {
			s.add(Finding{Path: PathListName, Line: f.StartLine, Rule: f.RuleID})
		}
	}
	return nil
}

func (s *scanner) checker() Checker {
	return Checker{Names: s.o.Names, Accounts: s.o.Accounts, AccountVars: s.o.AccountVars}
}

// structural runs the checks gitleaks lacks over the whole tree and over
// the range's added lines.
func (s *scanner) structural() error {
	c := s.checker()
	s.markLns = map[Loc]string{}
	s.structFired = map[Loc]bool{}
	for _, p := range s.paths {
		s.addAll(c.CheckPath(p))
		fi, err := os.Lstat(filepath.Join(s.treeDir, p))
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(s.treeDir, p))
		if err != nil {
			return err
		}
		s.checkLines(c, p, 1, content, true)
	}
	if s.o.Base == "" {
		return nil
	}
	out, err := s.git(nil, "diff", "--no-textconv", "--no-ext-diff", "--no-color", "-U0", s.o.Base+"..."+s.head)
	if err != nil {
		return err
	}
	path, line := "", 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "+++ "):
			path = strings.TrimPrefix(strings.TrimPrefix(l, "+++ "), "b/")
			if path != "/dev/null" {
				s.addAll(c.CheckPath(path))
			}
		case strings.HasPrefix(l, "@@ "):
			line = hunkStart(l)
		case strings.HasPrefix(l, "+"):
			s.checkLines(c, path, line, []byte(l[1:]), false)
			line++
		case strings.HasPrefix(l, "Binary files "):
			// A binary file the range adds: read its blob as bytes.
			if p := binaryPath(l); p != "" {
				blob, err := s.git(nil, "show", s.head+":"+p)
				if err == nil {
					s.checkLines(c, p, 1, blob, false)
				}
			}
		}
	}
	return sc.Err()
}

func (s *scanner) checkLines(c Checker, path string, first int, content []byte, tree bool) {
	for i, l := range strings.Split(string(content), "\n") {
		s.res.StructuralLines++
		loc := Loc{path, first + i}
		fs := c.CheckLine(l)
		if len(fs) > 0 && hasReasonedMarker(l) {
			// A reasoned marker exempts the line's structural findings,
			// as it exempts gitleaks', and is thereby shown to be needed.
			if tree {
				s.structFired[loc] = true
			}
			fs = nil
		}
		for _, f := range fs {
			s.add(Finding{Path: path, Line: loc.Line, Rule: f.Rule})
		}
		if tree && strings.Contains(l, marker) {
			s.markLns[loc] = l
		}
	}
}

func hasReasonedMarker(l string) bool {
	i := strings.Index(l, marker)
	return i >= 0 && strings.TrimSpace(l[i+len(marker):]) != ""
}

var hunkRe = regexp.MustCompile(`^@@ -[0-9,]+ \+([0-9]+)`)

func hunkStart(l string) int {
	if m := hunkRe.FindStringSubmatch(l); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

var binRe = regexp.MustCompile(`^Binary files .* and b/(.+) differ$`)

func binaryPath(l string) string {
	if m := binRe.FindStringSubmatch(l); m != nil {
		return m[1]
	}
	return ""
}

// markers checks every inline marker against a rescan that ignores them.
func (s *scanner) markers() error {
	s.res.Markers = len(s.markLns)
	if len(s.markLns) == 0 {
		return nil
	}
	_, fs, err := s.gitleaks(s.treeDir, nil, "dir", ".", "--ignore-gitleaks-allow")
	if err != nil {
		return err
	}
	fired := map[Loc]bool{}
	for loc := range s.structFired {
		fired[loc] = true
	}
	for _, f := range fs {
		fired[Loc{f.File, f.StartLine}] = true
	}
	s.addAll(CheckMarkers(s.markLns, fired))
	return nil
}

func (s *scanner) add(f Finding) { s.res.Findings = append(s.res.Findings, f) }

func (s *scanner) addAll(fs []Finding) {
	for _, f := range fs {
		s.add(f)
	}
}

func stripANSI(s string) string { return ansi.ReplaceAllString(s, "") }

func dedupe(fs []Finding) []Finding {
	seen := map[Finding]bool{}
	var out []Finding
	for _, f := range fs {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}
