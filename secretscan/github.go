package secretscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GitHub posts or updates the review's one comment on a pull request.
type GitHub struct {
	API    string // https://api.github.com
	Repo   string // owner/name
	Token  string // the job's GITHUB_TOKEN
	Client *http.Client
}

func (g *GitHub) do(ctx context.Context, method, path string, body any, into any) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.API, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	c := g.Client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("github %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, githubMaxResponse+1))
	if err != nil {
		return err
	}
	if len(raw) > githubMaxResponse {
		return fmt.Errorf("github %s %s: the response exceeds %d bytes", method, path, githubMaxResponse)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("github %s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if into != nil {
		return json.Unmarshal(raw, into)
	}
	return nil
}

// Upsert replaces the pull request's comment that carries CommentMarker,
// or creates one.
func (g *GitHub) Upsert(ctx context.Context, pr int, body string) error {
	for page := 1; page <= 10; page++ {
		var comments []struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
		}
		if err := g.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100&page=%d", g.Repo, pr, page), nil, &comments); err != nil {
			return err
		}
		for _, c := range comments {
			if strings.HasPrefix(c.Body, CommentMarker) {
				return g.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/comments/%d", g.Repo, c.ID), map[string]string{"body": body}, nil)
			}
		}
		if len(comments) < 100 {
			break
		}
	}
	return g.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/issues/%d/comments", g.Repo, pr), map[string]string{"body": body}, nil)
}

// CompletionReport is layer 2's own denominator: of the pull requests
// updated in a window, how many carry a review comment that completed.
type CompletionReport struct {
	PRs, Completed int
	NoComment      int
	Reasons        map[string]int // why layer 2 did not complete, by reason
}

// Completion reads the pull requests updated in the last days and their
// review comments (docs/design.md §6).
// githubPage is how many pull requests one list request asks for. A full
// pull-request object is tens of KB (body, labels, links), so 100 per page
// passed the 1 MiB cap the client once shared with Vornik's, and the cut
// JSON failed the first weekly self-test ("unexpected end of JSON input").
const githubPage = 30

// githubMaxResponse caps one GitHub response: room for a page of large
// pull-request objects. A response over it is an error that says so, never
// cut JSON.
const githubMaxResponse = 8 << 20

// githubMaxPages bounds the completion walk: 600 pull requests a week.
const githubMaxPages = 20

func (g *GitHub) Completion(ctx context.Context, since time.Time) (*CompletionReport, error) {
	r := &CompletionReport{Reasons: map[string]int{}}
	for page := 1; page <= githubMaxPages; page++ {
		var prs []struct {
			Number    int       `json:"number"`
			UpdatedAt time.Time `json:"updated_at"`
		}
		if err := g.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/pulls?state=all&sort=updated&direction=desc&per_page=%d&page=%d", g.Repo, githubPage, page), nil, &prs); err != nil {
			return nil, err
		}
		done := len(prs) < githubPage
		for _, pr := range prs {
			if pr.UpdatedAt.Before(since) {
				done = true
				break
			}
			r.PRs++
			body, err := g.reviewComment(ctx, pr.Number)
			if err != nil {
				return nil, err
			}
			switch {
			case body == "":
				r.NoComment++
			case strings.Contains(body, "Layer 2 did not complete:"):
				reason := body[strings.Index(body, "Layer 2 did not complete:")+len("Layer 2 did not complete:"):]
				reason, _, _ = strings.Cut(strings.TrimSpace(strings.TrimPrefix(reason, "**")), ".")
				r.Reasons[strings.TrimSpace(reason)]++
			default:
				r.Completed++
			}
		}
		if done {
			break
		}
	}
	return r, nil
}

func (g *GitHub) reviewComment(ctx context.Context, pr int) (string, error) {
	for page := 1; page <= 10; page++ {
		var comments []struct {
			Body string `json:"body"`
		}
		if err := g.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100&page=%d", g.Repo, pr, page), nil, &comments); err != nil {
			return "", err
		}
		for _, c := range comments {
			if strings.HasPrefix(c.Body, CommentMarker) {
				return c.Body, nil
			}
		}
		if len(comments) < 100 {
			break
		}
	}
	return "", nil
}
