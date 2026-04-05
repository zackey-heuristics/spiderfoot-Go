package sflib

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"time"

	"golang.org/x/time/rate"
)

// HTTPClientOpts configures an HTTPClient.
type HTTPClientOpts struct {
	// Timeout is the request timeout. Defaults to 15s.
	Timeout time.Duration
	// UserAgent is the User-Agent header. Defaults to a Firefox string.
	UserAgent string
	// MaxBodySize limits response body reads. Defaults to 10MB.
	MaxBodySize int64
	// RateLimit is requests per second. 0 means unlimited.
	RateLimit float64
}

// HTTPClient wraps http.Client with SpiderFoot module conveniences.
type HTTPClient struct {
	client    *http.Client
	userAgent string
	maxBody   int64
	limiter   *rate.Limiter
}

// NewHTTPClient creates an HTTPClient with the given options.
func NewHTTPClient(opts HTTPClientOpts) *HTTPClient {
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
	}
	if opts.MaxBodySize == 0 {
		opts.MaxBodySize = 10 << 20 // 10MB
	}

	jar, _ := cookiejar.New(nil)
	c := &HTTPClient{
		client: &http.Client{
			Timeout: opts.Timeout,
			Jar:     jar,
		},
		userAgent: opts.UserAgent,
		maxBody:   opts.MaxBodySize,
	}
	if opts.RateLimit > 0 {
		c.limiter = rate.NewLimiter(rate.Limit(opts.RateLimit), 1)
	}
	return c
}

// Response holds the result of an HTTP fetch.
type Response struct {
	// StatusCode is the HTTP status code.
	StatusCode int
	// Headers are the response headers.
	Headers http.Header
	// Body is the response body (truncated to MaxBodySize).
	Body string
	// FinalURL is the URL after redirects.
	FinalURL string
}

// FetchURL performs an HTTP GET and returns the response.
func (c *HTTPClient) FetchURL(ctx context.Context, url string) (*Response, error) {
	return c.doRequest(ctx, http.MethodGet, url, nil)
}

// PostJSON performs an HTTP POST with a JSON-like body and returns the response.
func (c *HTTPClient) PostJSON(ctx context.Context, url string, body io.Reader) (*Response, error) {
	return c.doRequest(ctx, http.MethodPost, url, body)
}

func (c *HTTPClient) doRequest(ctx context.Context, method, url string, body io.Reader) (*Response, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, c.maxBody)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       string(data),
		FinalURL:   resp.Request.URL.String(),
	}, nil
}
