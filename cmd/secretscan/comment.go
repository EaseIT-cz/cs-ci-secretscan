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

// runComment posts a comment that review wrote, in its own step: the step
// that holds the GitHub token holds no Vornik key and runs no scan.
//
//	secretscan comment --file FILE --pr N --repository OWNER/NAME
//
// The token is read from GITHUB_TOKEN. A comment without the tool's marker
// is refused, so the step can only post what review wrote. A failed post
// is reported and exits 0: layer 2 comments only.
func runComment(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("comment", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the comment review wrote")
	pr := fs.Int("pr", 0, "the pull request")
	repository := fs.String("repository", "", "owner/name")
	api := fs.String("github-api", "https://api.github.com", "the GitHub API")
	if err := fs.Parse(args); err != nil || *file == "" || *pr <= 0 || *repository == "" {
		fmt.Fprintln(stderr, "usage: secretscan comment --file FILE --pr N --repository OWNER/NAME")
		return 2
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintln(stderr, "secretscan comment:", err)
		return 2
	}
	body := string(raw)
	if !strings.HasPrefix(body, secretscan.CommentMarker) || len(body) > 60000 {
		fmt.Fprintln(stderr, "secretscan comment: not a review comment, or too long; refused")
		return 2
	}
	g := &secretscan.GitHub{API: *api, Repo: *repository, Token: os.Getenv("GITHUB_TOKEN")}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := g.Upsert(ctx, *pr, body); err != nil {
		fmt.Fprintln(stderr, "secretscan comment: not posted:", err)
	}
	return 0
}
