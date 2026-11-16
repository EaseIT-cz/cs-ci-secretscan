package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/EaseIT-cz/cs-ci-secretscan/secretscan"
)

func runReview(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", ".", "the git repository")
	base := fs.String("base", "", "the change's base revision")
	head := fs.String("head", "HEAD", "the change's head revision")
	config := fs.String("config", "", "the gitleaks config")
	ledgers := fs.String("ledgers", "", "the ledger directory")
	accountVars := fs.String("account-vars", "", "comma-separated account ids that are always findings")
	gitleaks := fs.String("gitleaks", "gitleaks", "the gitleaks binary")
	vornikURL := fs.String("vornik-url", "", "Vornik's companion MCP endpoint")
	prefix := fs.String("prefix", "", "the workflow id prefix, e.g. ns--secretscan--")
	pr := fs.Int("pr", 0, "the pull request to comment on")
	repository := fs.String("repository", "", "owner/name, for the comment")
	api := fs.String("github-api", "https://api.github.com", "the GitHub API")
	out := fs.String("out", "", "write the comment to this file")
	summary := fs.String("summary", "", "append the comment to this file")
	timeout := fs.Duration("timeout", 10*time.Minute, "the most layer 2 may take")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *base == "" || *vornikURL == "" || *prefix == "" {
		fmt.Fprintln(stderr, "secretscan review: --base, --vornik-url and --prefix are required")
		return 2
	}
	work, err := os.MkdirTemp("", "secretscan-review-")
	if err != nil {
		fmt.Fprintln(stderr, "secretscan:", err)
		return 2
	}
	defer os.RemoveAll(work)

	o := secretscan.Options{Repo: *repo, Base: *base, Head: *head, Config: *config, Gitleaks: *gitleaks, WorkDir: work}
	for _, l := range []struct {
		name string
		dst  **secretscan.Ledger
	}{{"accounts.allow", &o.Accounts}, {"names.allow", &o.Names}, {"skip.allow", &o.Skip}} {
		led, _, err := loadLedger(*ledgers, l.name)
		if err != nil {
			fmt.Fprintln(stderr, "secretscan:", err)
			return 2
		}
		*l.dst = led
	}
	for _, v := range strings.Split(*accountVars, ",") {
		if v = strings.TrimSpace(v); v != "" {
			o.AccountVars = append(o.AccountVars, v)
		}
	}
	headSHA, _ := gitOutput(*repo, "rev-parse", *head)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var rv *secretscan.Review
	if token := os.Getenv("VORNIK_TOKEN"); token == "" {
		rv = &secretscan.Review{Reason: "no Vornik key was given (VORNIK_TOKEN)"}
	} else {
		rv = secretscan.RunReview(ctx, secretscan.ReviewOptions{
			Scan:    o,
			Vornik:  &secretscan.Vornik{URL: *vornikURL, Token: token},
			Prefix:  *prefix,
			HeadSHA: headSHA,
		})
	}
	comment := secretscan.RenderComment(rv, 0, 0)
	fmt.Fprint(stdout, comment)
	for _, f := range []string{*out, *summary} {
		if f != "" {
			if err := appendFile(f, comment); err != nil {
				fmt.Fprintln(stderr, "secretscan:", err)
			}
		}
	}
	if *pr > 0 && *repository != "" {
		g := &secretscan.GitHub{API: *api, Repo: *repository, Token: os.Getenv("GITHUB_TOKEN")}
		pctx, pcancel := context.WithTimeout(context.Background(), time.Minute)
		defer pcancel()
		if err := g.Upsert(pctx, *pr, comment); err != nil {
			// The comment is also in the job summary; a failed post is reported, not fatal.
			fmt.Fprintln(stderr, "secretscan: the comment was not posted:", err)
		}
	}
	return 0
}

func gitOutput(repo string, args ...string) (string, error) {
	b, err := execGit(repo, args...)
	return strings.TrimSpace(string(b)), err
}
