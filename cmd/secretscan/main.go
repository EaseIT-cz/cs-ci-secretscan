// Command secretscan runs a layered secret scan (docs/design.md).
//
//	secretscan scan --repo DIR [--base REV] [--head REV] [--config FILE]
//	    [--ledgers DIR] [--account-vars ID,ID] [--report FILE] [--summary FILE]
//	    [--gitleaks PATH]
//
// runs layer 1 over the repository's index, its history and, with --base,
// the range base..head. It prints what it examined and every finding as
// path, line and rule, never a value. --ledgers names a directory holding
// accounts.allow, names.allow and skip.allow; a missing file is an empty
// ledger, and the summary says so. --report writes one JSON object per
// finding; --summary appends a Markdown summary (for $GITHUB_STEP_SUMMARY).
//
// Exit status: 0 clean, 1 findings, 2 a tool or usage error, which is
// never a clean result.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/EaseIT-cz/cs-ci-secretscan/secretscan"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprintln(stderr, "usage: secretscan scan --repo DIR [flags]")
		return 2
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", ".", "the git repository")
	base := fs.String("base", "", "the range's base revision")
	head := fs.String("head", "", "the range's head revision (default HEAD)")
	config := fs.String("config", "", "the gitleaks config (default: gitleaks' rules only)")
	ledgers := fs.String("ledgers", "", "the directory holding accounts.allow, names.allow, skip.allow")
	accountVars := fs.String("account-vars", "", "comma-separated account ids that are always findings")
	report := fs.String("report", "", "write findings as JSON lines to this file")
	summary := fs.String("summary", "", "append a Markdown summary to this file")
	gitleaks := fs.String("gitleaks", "gitleaks", "the gitleaks binary")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	work, err := os.MkdirTemp("", "secretscan-")
	if err != nil {
		fmt.Fprintln(stderr, "secretscan:", err)
		return 2
	}
	defer os.RemoveAll(work)

	o := secretscan.Options{Repo: *repo, Base: *base, Head: *head, Config: *config, Gitleaks: *gitleaks, WorkDir: work}
	var notes []string
	for _, l := range []struct {
		name string
		dst  **secretscan.Ledger
	}{{"accounts.allow", &o.Accounts}, {"names.allow", &o.Names}, {"skip.allow", &o.Skip}} {
		led, note, err := loadLedger(*ledgers, l.name)
		if err != nil {
			fmt.Fprintln(stderr, "secretscan:", err)
			return 2
		}
		*l.dst = led
		notes = append(notes, note)
	}
	for _, v := range strings.Split(*accountVars, ",") {
		if v = strings.TrimSpace(v); v != "" {
			o.AccountVars = append(o.AccountVars, v)
		}
	}

	res, err := secretscan.Scan(o)
	if err != nil {
		fmt.Fprintln(stderr, "secretscan: refused, coverage unproven:", err)
		return 2
	}
	text := render(res, notes)
	fmt.Fprint(stdout, text)
	if *summary != "" {
		if err := appendFile(*summary, text); err != nil {
			fmt.Fprintln(stderr, "secretscan:", err)
			return 2
		}
	}
	if *report != "" {
		if err := writeReport(*report, res.Findings); err != nil {
			fmt.Fprintln(stderr, "secretscan:", err)
			return 2
		}
	}
	if len(res.Findings) > 0 {
		return 1
	}
	return 0
}

func loadLedger(dir, name string) (*secretscan.Ledger, string, error) {
	if dir == "" {
		return nil, name + ": not given (empty)", nil
	}
	f, err := os.Open(filepath.Join(dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, name + ": absent (empty)", nil
	}
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	l, err := secretscan.ParseLedger(name, f)
	if err != nil {
		return nil, "", err
	}
	return l, fmt.Sprintf("%s: %d entries", name, l.Len()), nil
}

// render states what was examined before what was found, so a clean
// result always carries its denominator.
func render(r *secretscan.Result, notes []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## secretscan: layer 1\n\n")
	fmt.Fprintf(&b, "| examined | count |\n|---|---|\n")
	fmt.Fprintf(&b, "| tracked files | %d |\n", r.Tree.TrackedFiles)
	fmt.Fprintf(&b, "| tracked bytes, scanned + skipped | %d = %d + %d |\n", r.Tree.TrackedBytes, r.Tree.ScannedBytes, r.Tree.SkippedBytes)
	fmt.Fprintf(&b, "| skipped files rescanned through stdin | %d |\n", len(r.StdinRescanned))
	fmt.Fprintf(&b, "| skipped files exempt by skip.allow | %d |\n", len(r.SkipExempt))
	fmt.Fprintf(&b, "| history commits that add a line | %d |\n", r.HistoryCommits)
	fmt.Fprintf(&b, "| range commits that add a line | %d |\n", r.RangeCommits)
	fmt.Fprintf(&b, "| commit-message bytes | %d |\n", r.MessageBytes)
	fmt.Fprintf(&b, "| distinct paths | %d |\n", r.PathCount)
	fmt.Fprintf(&b, "| lines through the structural checks | %d |\n", r.StructuralLines)
	fmt.Fprintf(&b, "| inline markers | %d |\n\n", r.Markers)
	fmt.Fprintf(&b, "Ledgers: %s.\n\n", strings.Join(notes, "; "))
	if len(r.Findings) == 0 {
		fmt.Fprintf(&b, "**No findings.**\n")
		return b.String()
	}
	fmt.Fprintf(&b, "**%d finding(s)** (path, line, rule; values are never printed):\n\n", len(r.Findings))
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "- `%s`\n", strings.ReplaceAll(f.String(), "`", "'"))
	}
	return b.String()
}

func appendFile(path, text string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func writeReport(path string, fs []secretscan.Finding) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, x := range fs {
		rec := map[string]any{"fingerprint": x.String(), "path": x.Path, "line": x.Line, "rule": x.Rule}
		if err := enc.Encode(rec); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}
