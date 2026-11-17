package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/EaseIT-cz/cs-ci-secretscan/secretscan"
)

// runSelftest runs layer 4 (docs/design.md §6):
//
//	secretscan selftest layer1 [--gitleaks PATH] [--values FILE] [--summary FILE]
//	secretscan selftest layer2 --vornik-url URL --prefix P [--floors FILE] [...]
//
// It writes the planted values to --values (0600) for the sweep, prints
// checks by name and counts, never a value, and exits 1 on a failure.
// layer2 reads the Vornik key from VORNIK_TOKEN.
func runSelftest(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "layer1" && args[0] != "layer2") {
		fmt.Fprintln(stderr, "usage: secretscan selftest layer1|layer2 [flags]")
		return 2
	}
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	gitleaks := fs.String("gitleaks", "gitleaks", "the gitleaks binary")
	values := fs.String("values", "", "write the planted values here (0600), for the sweep")
	summary := fs.String("summary", "", "append the report to this file")
	vornikURL := fs.String("vornik-url", "", "layer2: Vornik's companion MCP endpoint")
	prefix := fs.String("prefix", "", "layer2: the workflow id prefix")
	floors := fs.String("floors", "", "layer2: the floors file (FLOOR_DETECTIONS, CEILING_DECOYS)")
	timeout := fs.Duration("timeout", 15*time.Minute, "layer2: the most it may take")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	work, err := os.MkdirTemp("", "secretscan-selftest-")
	if err != nil {
		fmt.Fprintln(stderr, "secretscan:", err)
		return 2
	}
	defer os.RemoveAll(work)
	var r *secretscan.SelftestReport
	title := "layer 1 (nightly)"
	if args[0] == "layer1" {
		r, err = secretscan.Layer1Selftest(*gitleaks, work)
	} else {
		title = "layers 2 and 3 (weekly)"
		if *vornikURL == "" || *prefix == "" || os.Getenv("VORNIK_TOKEN") == "" {
			fmt.Fprintln(stderr, "secretscan selftest layer2: --vornik-url, --prefix and VORNIK_TOKEN are required")
			return 2
		}
		f, ferr := readFloors(*floors)
		if ferr != nil {
			fmt.Fprintln(stderr, "secretscan:", ferr)
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		r, err = secretscan.Layer2Selftest(ctx, &secretscan.Vornik{URL: *vornikURL, Token: os.Getenv("VORNIK_TOKEN")}, *prefix, *gitleaks, work, f)
	}
	if err != nil {
		fmt.Fprintln(stderr, "secretscan selftest:", err)
		return 2
	}
	if *values != "" {
		if err := os.WriteFile(*values, []byte(strings.Join(r.Values, "\n")+"\n"), 0o600); err != nil {
			fmt.Fprintln(stderr, "secretscan:", err)
			return 2
		}
	}
	text := secretscan.RenderSelftest(title, r)
	fmt.Fprint(stdout, text)
	if *summary != "" {
		_ = appendFile(*summary, text)
	}
	if !r.Pass {
		return 1
	}
	return 0
}

// readFloors reads FLOOR_DETECTIONS and CEILING_DECOYS; a missing file or
// unset key means the floors are not set yet.
func readFloors(path string) (secretscan.Floors, error) {
	var f secretscan.Floors
	if path == "" {
		return f, nil
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	defer file.Close()
	got := 0
	s := bufio.NewScanner(file)
	for s.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(s.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return f, fmt.Errorf("floors: %s: %w", k, err)
		}
		switch strings.TrimSpace(k) {
		case "FLOOR_DETECTIONS":
			f.MinDetections, got = n, got+1
		case "CEILING_DECOYS":
			f.MaxDecoys, got = n, got+1
		}
	}
	f.Set = got == 2
	return f, s.Err()
}

// runSweep searches files for the planted values (docs/design.md §6):
//
//	secretscan sweep --values FILE FILE...
//
// It plants one value in a control file first and fails if it cannot find
// it; any other hit fails too. It prints file names and counts, never a value.
func runSweep(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sweep", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := fs.String("values", "", "the planted values, one per line")
	if err := fs.Parse(args); err != nil || *values == "" {
		fmt.Fprintln(stderr, "usage: secretscan sweep --values FILE FILE...")
		return 2
	}
	raw, err := os.ReadFile(*values)
	if err != nil {
		fmt.Fprintln(stderr, "secretscan sweep:", err)
		return 2
	}
	var vs []string
	for _, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			vs = append(vs, l)
		}
	}
	dir, err := os.MkdirTemp("", "secretscan-sweep-")
	if err != nil {
		return 2
	}
	defer os.RemoveAll(dir)
	var files []string
	for _, f := range fs.Args() {
		if _, err := os.Stat(f); err == nil {
			files = append(files, f)
		}
	}
	hits, control, err := secretscan.Sweep(vs, files, dir)
	if err != nil {
		fmt.Fprintln(stderr, "secretscan sweep:", err)
		return 2
	}
	fmt.Fprintf(stdout, "sweep: %d planted value(s) searched in %d file(s); positive control found: %v; files holding a value: %d\n", len(vs), len(files), control, len(hits))
	for _, h := range hits {
		fmt.Fprintf(stdout, "  holds a planted value: %s\n", h)
	}
	if !control || len(hits) > 0 {
		return 1
	}
	return 0
}

// runCompletion reports layer 2's own denominator (docs/design.md §6):
//
//	secretscan completion --repository OWNER/NAME [--days 7] [--summary FILE]
//
// It reads GITHUB_TOKEN, and exits 1 when pull requests carried review
// comments but none completed; a partial week is reported, not failed.
func runCompletion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("completion", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repository := fs.String("repository", "", "owner/name")
	days := fs.Int("days", 7, "the window")
	api := fs.String("github-api", "https://api.github.com", "the GitHub API")
	summary := fs.String("summary", "", "append the report to this file")
	if err := fs.Parse(args); err != nil || *repository == "" {
		fmt.Fprintln(stderr, "usage: secretscan completion --repository OWNER/NAME [--days N]")
		return 2
	}
	g := &secretscan.GitHub{API: *api, Repo: *repository, Token: os.Getenv("GITHUB_TOKEN")}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	r, err := g.Completion(ctx, time.Now().Add(-time.Duration(*days)*24*time.Hour))
	if err != nil {
		fmt.Fprintln(stderr, "secretscan completion:", err)
		return 2
	}
	reviewed := r.PRs - r.NoComment
	var b strings.Builder
	fmt.Fprintf(&b, "## secretscan: layer 2 completion\n\nLayer 2 completed for %d of %d pull request(s) with a review comment in %d days (%d more had no review comment).\n", r.Completed, reviewed, *days, r.NoComment)
	for reason, n := range r.Reasons {
		fmt.Fprintf(&b, "- did not complete, %d: %s\n", n, strings.NewReplacer("`", "'", "|", "/").Replace(reason))
	}
	fmt.Fprint(stdout, b.String())
	if *summary != "" {
		_ = appendFile(*summary, b.String())
	}
	if reviewed > 0 && r.Completed == 0 {
		return 1
	}
	return 0
}
