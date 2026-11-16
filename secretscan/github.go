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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
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
