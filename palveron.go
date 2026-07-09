// Package palveron provides the official Go SDK for the PALVERON AI Governance Platform.
//
// Usage:
//
//	client := palveron.NewClient("pv_live_xxx")
//	result, err := client.Verify(ctx, &palveron.VerifyRequest{
//	    Prompt: "User input here",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if result.Decision == palveron.Blocked {
//	    log.Fatalf("Blocked: %s", result.Reason)
//	}
package palveron

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
	Version        = "1.1.0"
	DefaultBaseURL = "https://gateway.palveron.com"
	DefaultTimeout = 30 * time.Second
)

// Decision represents a governance decision returned by /api/v1/verify.
//
// Sprint 87 — the gateway maps each Decision onto a matching HTTP status:
//
//	PASSED / ALLOWED / MODIFIED / FLAGGED / POLICY_CHANGE → 200 OK
//	PENDING_APPROVAL                                      → 202 Accepted
//	BLOCKED                                               → 403 Forbidden
//	RATE_LIMITED                                          → 429 Too Many Requests
//	ERROR                                                 → transport/internal failure
//
// RATE_LIMITED is synthesised client-side when the gateway returns 429
// with the tier-rate-limit body shape (no decision field) so callers
// can branch on Decision uniformly instead of also checking for errors.
type Decision string

const (
	Passed          Decision = "PASSED"
	Allowed         Decision = "ALLOWED"
	Blocked         Decision = "BLOCKED"
	Modified        Decision = "MODIFIED"
	Flagged         Decision = "FLAGGED"
	PendingApproval Decision = "PENDING_APPROVAL"
	PolicyChange    Decision = "POLICY_CHANGE"
	RateLimited     Decision = "RATE_LIMITED"
	Error           Decision = "ERROR"
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
		return nil, fmt.Errorf("palveron: read file: %w", err)
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

	// RetryAfterMs is populated when Decision == RateLimited. Honour
	// it before issuing the next request. Derived from the gateway's
	// Retry-After header (in milliseconds).
	RetryAfterMs int64 `json:"-"`

	// HTTPStatus is the HTTP status code that produced this response
	// (200, 202, 403, 429). Useful for observability.
	HTTPStatus int `json:"-"`
}

// IsAllowed returns true if the decision is ALLOWED or PASSED.
func (r *VerifyResponse) IsAllowed() bool { return r.Decision == Allowed || r.Decision == Passed }

// IsBlocked returns true if the decision is BLOCKED.
func (r *VerifyResponse) IsBlocked() bool { return r.Decision == Blocked }

// IsPendingApproval returns true if the request is queued for human approval.
func (r *VerifyResponse) IsPendingApproval() bool { return r.Decision == PendingApproval }

// IsRateLimited returns true if the request was rejected by the tier rate-limit.
func (r *VerifyResponse) IsRateLimited() bool { return r.Decision == RateLimited }

// HealthResponse represents the gateway health status.
type HealthResponse struct {
	Status  string  `json:"status"`
	Version string  `json:"version"`
	Uptime  float64 `json:"uptime"`
}

// ── Errors ──────────────────────────────────────────────────

// PalveronError is the base error type for all SDK errors.
type PalveronError struct {
	Code       string
	Message    string
	StatusCode int
	RequestID  string
	Retryable  bool
}

func (e *PalveronError) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("palveron: %s (code=%s, status=%d, request_id=%s)", e.Message, e.Code, e.StatusCode, e.RequestID)
	}
	return fmt.Sprintf("palveron: %s (code=%s, status=%d)", e.Message, e.Code, e.StatusCode)
}

// IsAuthError returns true if the error is an authentication failure.
func IsAuthError(err error) bool {
	if e, ok := err.(*PalveronError); ok {
		return e.StatusCode == 401
	}
	return false
}

// IsRateLimited returns true if the error is a rate limit.
func IsRateLimited(err error) bool {
	if e, ok := err.(*PalveronError); ok {
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

// Client is the PALVERON API client.
type Client struct {
	apiKey     string
	baseURL    string
	timeout    time.Duration
	maxRetries int
	http       *http.Client
	headers    map[string]string
	circuit    *circuitBreaker
}

// NewClient creates a new PALVERON client.
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
//
// Sprint 87 — the gateway maps the Decision field onto an HTTP status
// (200 PASSED / 202 PENDING_APPROVAL / 403 BLOCKED / 429 RATE_LIMITED).
// Verify treats all four as legitimate governance outcomes and returns
// a *VerifyResponse for each; it does not error on 403 or 429. Only
// transport, auth, validation, and 5xx failures return an error.
func (c *Client) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	start := time.Now()
	var resp VerifyResponse
	status, retryAfterMs, err := c.doGoverned(ctx, "POST", "/api/v1/verify", req, &resp)
	if err != nil {
		return nil, err
	}
	resp.LatencyMs = float64(time.Since(start).Milliseconds())
	resp.HTTPStatus = status
	resp.RetryAfterMs = retryAfterMs
	// Synthesise decision from HTTP status when the body has none
	// (notably 429 rate-limit responses carry a different body shape).
	if resp.Decision == "" {
		resp.Decision = decisionFromStatus(status)
	}
	return &resp, nil
}

// decisionFromStatus synthesises a Decision from an HTTP status code
// when the response body had no Decision field.
func decisionFromStatus(status int) Decision {
	switch {
	case status == 429:
		return RateLimited
	case status == 403:
		return Blocked
	case status == 202:
		return PendingApproval
	case status >= 200 && status < 300:
		return Passed
	default:
		return Error
	}
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
	_, _, err := c.doInner(ctx, method, path, body, out, false)
	return err
}

// doGoverned issues a request that accepts governance-status responses
// (202 / 403 / 429) as success — used by Verify. Returns the HTTP
// status code that produced the body and, for 429, the Retry-After
// header parsed into milliseconds.
func (c *Client) doGoverned(ctx context.Context, method, path string, body, out interface{}) (int, int64, error) {
	return c.doInner(ctx, method, path, body, out, true)
}

func (c *Client) doInner(ctx context.Context, method, path string, body, out interface{}, expectGovernance bool) (int, int64, error) {
	if !c.circuit.canRequest() {
		return 0, 0, &PalveronError{Code: "CIRCUIT_OPEN", Message: "circuit breaker open", StatusCode: 503}
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			delay := backoff(attempt)
			select {
			case <-ctx.Done():
				return 0, 0, ctx.Err()
			case <-time.After(delay):
			}
		}

		reqID := makeRequestID()
		status, retryAfterMs, err := c.doOnce(ctx, method, path, body, out, reqID, expectGovernance)
		if err == nil {
			c.circuit.onSuccess()
			return status, retryAfterMs, nil
		}

		if ve, ok := err.(*PalveronError); ok && !ve.Retryable {
			return 0, 0, ve
		}

		c.circuit.onFailure()
		lastErr = err
	}
	return 0, 0, lastErr
}

func (c *Client) doOnce(ctx context.Context, method, path string, body, out interface{}, reqID string, expectGovernance bool) (int, int64, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, 0, fmt.Errorf("palveron: marshal: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return 0, 0, fmt.Errorf("palveron: create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sdk-go/"+Version)
	req.Header.Set("X-Request-ID", reqID)
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, 0, &PalveronError{Code: "NETWORK_ERROR", Message: err.Error(), Retryable: true, RequestID: reqID}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Sprint 87 — for governance calls, 202 (PENDING_APPROVAL)
		// arrives here alongside 200. Decode and let the caller branch
		// on the Decision field.
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
			return resp.StatusCode, 0, err
		}
		return resp.StatusCode, 0, nil
	}

	rid := resp.Header.Get("X-Request-ID")
	if rid == "" {
		rid = reqID
	}

	// ── Sprint 87 governance status codes ──
	// Verify-path 403 (BLOCKED) and 429 (RATE_LIMITED) carry actionable
	// bodies and are *not* errors. The caller asked for governance
	// semantics by setting expectGovernance; surface the body instead.
	if expectGovernance && (resp.StatusCode == 403 || resp.StatusCode == 429) {
		// Decode body — 403 has a verify-shaped body, 429 has the
		// rate-limit error shape. The caller post-processes either way.
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
			// Body wasn't valid JSON, fall through to standard error
			// handling so the caller sees a transport error rather than
			// a confusingly-empty VerifyResponse.
			return 0, 0, &PalveronError{Code: "DECODE_ERROR", Message: err.Error(), StatusCode: resp.StatusCode, RequestID: rid}
		}
		retryAfterMs := int64(0)
		if resp.StatusCode == 429 {
			retryAfterMs = parseRetryAfter(resp.Header.Get("Retry-After"))
		}
		return resp.StatusCode, retryAfterMs, nil
	}

	switch resp.StatusCode {
	case 401:
		return 0, 0, &PalveronError{Code: "AUTH_FAILED", Message: "invalid API key", StatusCode: 401, RequestID: rid}
	case 429:
		retryAfterMs := parseRetryAfter(resp.Header.Get("Retry-After"))
		return 0, retryAfterMs, &PalveronError{Code: "RATE_LIMITED", Message: "rate limit exceeded", StatusCode: 429, RequestID: rid, Retryable: true}
	case 400:
		msg := errorMessageFromBody(resp.Body)
		if msg == "" {
			msg = "Bad request"
		}
		return 0, 0, &PalveronError{Code: "VALIDATION", Message: msg, StatusCode: 400, RequestID: rid}
	}

	if resp.StatusCode >= 500 {
		return 0, 0, &PalveronError{Code: "SERVER_ERROR", Message: fmt.Sprintf("HTTP %d", resp.StatusCode), StatusCode: resp.StatusCode, RequestID: rid, Retryable: true}
	}

	return 0, 0, &PalveronError{Code: "CLIENT_ERROR", Message: fmt.Sprintf("HTTP %d", resp.StatusCode), StatusCode: resp.StatusCode, RequestID: rid}
}

// errorMessageFromBody extracts a human-readable message from a gateway
// error body, tolerant of BOTH contract shapes:
//   - legacy flat string: {"error":"message"}
//   - structured object:  {"error":{"code","message","request_id"}}
// Returns "" when the body carries no usable message (caller supplies a default).
func errorMessageFromBody(r io.Reader) string {
	data, err := io.ReadAll(r)
	if err != nil || len(data) == 0 {
		return ""
	}
	var probe struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
	}
	if json.Unmarshal(data, &probe) != nil {
		return ""
	}
	if len(probe.Error) > 0 {
		var obj struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(probe.Error, &obj) == nil && obj.Message != "" {
			return obj.Message
		}
		var str string
		if json.Unmarshal(probe.Error, &str) == nil && str != "" {
			return str
		}
	}
	return probe.Message
}

// parseRetryAfter parses an HTTP Retry-After header into milliseconds.
// Supports both delta-seconds (RFC 7231 §7.1.3) and HTTP-date forms.
// Returns 0 when the header is missing or unparseable.
func parseRetryAfter(value string) int64 {
	if value == "" {
		return 0
	}
	// Try delta-seconds
	var seconds float64
	if _, err := fmt.Sscanf(value, "%f", &seconds); err == nil && seconds >= 0 {
		return int64(seconds * 1000)
	}
	// Try HTTP-date
	if t, err := http.ParseTime(value); err == nil {
		delta := time.Until(t).Milliseconds()
		if delta < 0 {
			return 0
		}
		return delta
	}
	return 0
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
	return fmt.Sprintf("pv_%x_%x", time.Now().UnixMilli(), rand.Int31())
}
