// Package vexis provides the official Go SDK for the VEXIS AI Governance Platform.
//
// Usage:
//
//	client := vexis.NewClient("gp_live_xxx")
//	result, err := client.Verify(ctx, &vexis.VerifyRequest{
//	    Prompt: "User input here",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if result.Decision == vexis.Blocked {
//	    log.Fatalf("Blocked: %s", result.Reason)
//	}
package vexis

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	Version        = "0.4.0"
	DefaultBaseURL = "https://gateway.vexis.io"
	DefaultTimeout = 30 * time.Second
)

// Decision represents a governance decision.
type Decision string

const (
	Allowed  Decision = "ALLOWED"
	Blocked  Decision = "BLOCKED"
	Modified Decision = "MODIFIED"
	Error    Decision = "ERROR"
)

// ── Request / Response Types ────────────────────────────────

// Attachment represents a multi-modal file attachment.
type Attachment struct {
	ContentType string                 `json:"content_type"`
	Data        string                 `json:"data"` // Base64
	Filename    string                 `json:"filename,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AttachmentFromFile creates an Attachment from a local file path.
func AttachmentFromFile(path string) (*Attachment, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vexis: read file: %w", err)
	}
	ct := mime.TypeByExtension(filepath.Ext(path))
	if ct == "" {
		ct = "application/octet-stream"
	}
	return &Attachment{
		ContentType: ct,
		Data:        base64.StdEncoding.EncodeToString(data),
		Filename:    filepath.Base(path),
		Metadata:    map[string]interface{}{"size_bytes": len(data)},
	}, nil
}

// RequestContext provides agentic context for MCP/tool chains.
type RequestContext struct {
	MCPServer    string `json:"mcp_server,omitempty"`
	ToolName     string `json:"tool_name,omitempty"`
	ChainDepth   int    `json:"chain_depth,omitempty"`
	SourceSystem string `json:"source_system,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
}

// VerifyRequest is the input for a governance check.
type VerifyRequest struct {
	Prompt        string                 `json:"prompt"`
	ExtractedText string                 `json:"extracted_text,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	Attachments   []Attachment           `json:"attachments,omitempty"`
	Context       *RequestContext        `json:"context,omitempty"`
}

// Finding represents a security finding from content analysis.
type Finding struct {
	Risk        string  `json:"risk"`
	Category    string  `json:"category"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// VerifyResponse is the output of a governance check.
type VerifyResponse struct {
	Decision      Decision  `json:"decision"`
	Output        string    `json:"output"`
	Reason        string    `json:"reason"`
	TraceID       string    `json:"trace_id"`
	IntegrityHash string    `json:"integrity_hash"`
	ShouldAnchor  bool      `json:"should_anchor"`
	FlareStatus   string    `json:"flare_status"`
	FlareTxHash   *string   `json:"flare_tx_hash"`
	ContentType   string    `json:"content_type"`
	Findings      []Finding `json:"findings"`
	LatencyMs     float64   `json:"-"` // Client-measured
}

// IsAllowed returns true if the decision is ALLOWED.
func (r *VerifyResponse) IsAllowed() bool { return r.Decision == Allowed }

// IsBlocked returns true if the decision is BLOCKED.
func (r *VerifyResponse) IsBlocked() bool { return r.Decision == Blocked }

// HealthResponse represents the gateway health status.
type HealthResponse struct {
	Status  string  `json:"status"`
	Version string  `json:"version"`
	Uptime  float64 `json:"uptime"`
}

// ── Errors ──────────────────────────────────────────────────

// VexisError is the base error type for all SDK errors.
type VexisError struct {
	Code       string
	Message    string
	StatusCode int
	RequestID  string
	Retryable  bool
}

func (e *VexisError) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("vexis: %s (code=%s, status=%d, request_id=%s)", e.Message, e.Code, e.StatusCode, e.RequestID)
	}
	return fmt.Sprintf("vexis: %s (code=%s, status=%d)", e.Message, e.Code, e.StatusCode)
}

// IsAuthError returns true if the error is an authentication failure.
func IsAuthError(err error) bool {
	if e, ok := err.(*VexisError); ok {
		return e.StatusCode == 401
	}
	return false
}

// IsRateLimited returns true if the error is a rate limit.
func IsRateLimited(err error) bool {
	if e, ok := err.(*VexisError); ok {
		return e.StatusCode == 429
	}
	return false
}

// ── Circuit Breaker ─────────────────────────────────────────

type circuitBreaker struct {
	mu        sync.Mutex
	failures  int
	threshold int
	cooldown  time.Duration
	lastFail  time.Time
	state     string // "closed", "open", "half-open"
}

func newCircuitBreaker(threshold int, cooldown time.Duration) *circuitBreaker {
	return &circuitBreaker{threshold: threshold, cooldown: cooldown, state: "closed"}
}

func (cb *circuitBreaker) canRequest() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case "closed":
		return true
	case "open":
		if time.Since(cb.lastFail) >= cb.cooldown {
			cb.state = "half-open"
			return true
		}
		return false
	default:
		return true
	}
}

func (cb *circuitBreaker) onSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = "closed"
}

func (cb *circuitBreaker) onFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFail = time.Now()
	if cb.failures >= cb.threshold {
		cb.state = "open"
	}
}

// ── Client Options ──────────────────────────────────────────

// Option configures the Client.
type Option func(*Client)

// WithBaseURL sets a custom gateway URL (e.g., for on-prem).
func WithBaseURL(url string) Option { return func(c *Client) { c.baseURL = url } }

// WithTimeout sets the request timeout.
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.timeout = d } }

// WithMaxRetries sets max retry attempts.
func WithMaxRetries(n int) Option { return func(c *Client) { c.maxRetries = n } }

// WithHTTPClient sets a custom http.Client (for proxies, TLS config, etc.).
func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.http = hc } }

// WithHeaders adds custom headers to every request.
func WithHeaders(h map[string]string) Option { return func(c *Client) { c.headers = h } }

// ── Client ──────────────────────────────────────────────────

// Client is the VEXIS API client.
type Client struct {
	apiKey     string
	baseURL    string
	timeout    time.Duration
	maxRetries int
	http       *http.Client
	headers    map[string]string
	circuit    *circuitBreaker
}

// NewClient creates a new VEXIS client.
func NewClient(apiKey string, opts ...Option) *Client {
	c := &Client{
		apiKey:     apiKey,
		baseURL:    DefaultBaseURL,
		timeout:    DefaultTimeout,
		maxRetries: 3,
		circuit:    newCircuitBreaker(5, 30*time.Second),
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: c.timeout}
	}
	return c
}

// Verify sends a governance verification request.
func (c *Client) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	start := time.Now()
	var resp VerifyResponse
	if err := c.do(ctx, "POST", "/api/v1/verify", req, &resp); err != nil {
		return nil, err
	}
	resp.LatencyMs = float64(time.Since(start).Milliseconds())
	return &resp, nil
}

// Check is a convenience method for text-only verification.
func (c *Client) Check(ctx context.Context, prompt string) (*VerifyResponse, error) {
	return c.Verify(ctx, &VerifyRequest{Prompt: prompt})
}

// VerifyFile verifies a prompt with a file attachment.
func (c *Client) VerifyFile(ctx context.Context, prompt, path string) (*VerifyResponse, error) {
	att, err := AttachmentFromFile(path)
	if err != nil {
		return nil, err
	}
	return c.Verify(ctx, &VerifyRequest{Prompt: prompt, Attachments: []Attachment{*att}})
}

// Health checks the gateway health.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var resp HealthResponse
	if err := c.do(ctx, "GET", "/health", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out interface{}) error {
	if !c.circuit.canRequest() {
		return &VexisError{Code: "CIRCUIT_OPEN", Message: "circuit breaker open", StatusCode: 503}
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			delay := backoff(attempt)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		reqID := makeRequestID()
		err := c.doOnce(ctx, method, path, body, out, reqID)
		if err == nil {
			c.circuit.onSuccess()
			return nil
		}

		if ve, ok := err.(*VexisError); ok && !ve.Retryable {
			return ve
		}

		c.circuit.onFailure()
		lastErr = err
	}
	return lastErr
}

func (c *Client) doOnce(ctx context.Context, method, path string, body, out interface{}, reqID string) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("vexis: marshal: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("vexis: create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vexis-sdk-go/"+Version)
	req.Header.Set("X-Request-ID", reqID)
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return &VexisError{Code: "NETWORK_ERROR", Message: err.Error(), Retryable: true, RequestID: reqID}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return json.NewDecoder(resp.Body).Decode(out)
	}

	rid := resp.Header.Get("X-Request-ID")
	if rid == "" {
		rid = reqID
	}

	switch resp.StatusCode {
	case 401:
		return &VexisError{Code: "AUTH_FAILED", Message: "invalid API key", StatusCode: 401, RequestID: rid}
	case 429:
		return &VexisError{Code: "RATE_LIMITED", Message: "rate limit exceeded", StatusCode: 429, RequestID: rid, Retryable: true}
	case 400:
		var errBody struct{ Error string `json:"error"` }
		json.NewDecoder(resp.Body).Decode(&errBody)
		return &VexisError{Code: "VALIDATION", Message: errBody.Error, StatusCode: 400, RequestID: rid}
	}

	if resp.StatusCode >= 500 {
		return &VexisError{Code: "SERVER_ERROR", Message: fmt.Sprintf("HTTP %d", resp.StatusCode), StatusCode: resp.StatusCode, RequestID: rid, Retryable: true}
	}

	return &VexisError{Code: "CLIENT_ERROR", Message: fmt.Sprintf("HTTP %d", resp.StatusCode), StatusCode: resp.StatusCode, RequestID: rid}
}

func backoff(attempt int) time.Duration {
	base := 500 * time.Millisecond * time.Duration(math.Pow(2, float64(attempt-1)))
	jitter := time.Duration(rand.Int63n(int64(base) / 5))
	d := base + jitter
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

func makeRequestID() string {
	return fmt.Sprintf("vx_%x_%x", time.Now().UnixMilli(), rand.Int31())
}
