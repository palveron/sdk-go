# Changelog

All notable changes to the Palveron Go SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.0] — 2026-05-19

### Changed
- `Verify()` now treats the gateway's Sprint-87 HTTP semantics as governance
  decisions rather than errors:
  - `200 OK` → `Decision: Passed | Modified | Flagged | PolicyChange`
  - `202 Accepted` → `Decision: PendingApproval`
  - `403 Forbidden` → `Decision: Blocked`
  - `429 Too Many Requests` → `Decision: RateLimited` (synthesised) with
    `VerifyResponse.RetryAfterMs` parsed from `Retry-After`
- Previous behaviour: 403/429 returned `*PalveronError`. New behaviour: only
  transport / auth / 400 / 5xx failures return an error. Every governance
  outcome flows through `VerifyResponse.Decision`.
- `Health()` and any future non-verify endpoint keep the strict
  error-on-non-2xx behaviour so 429 on idempotent reads still retries.
- `Version` constant fixed: was `"0.5.0"` even after the 1.0 release.

### Added
- New `Decision` constants: `Passed`, `Flagged`, `PendingApproval`,
  `PolicyChange`, `RateLimited` (alongside the existing `Allowed`,
  `Blocked`, `Modified`, `Error`).
- `VerifyResponse.RetryAfterMs int64` — populated when `Decision ==
  RateLimited`.
- `VerifyResponse.HTTPStatus int` — the HTTP status code that produced
  the response.
- `IsPendingApproval()` and `IsRateLimited()` methods.
- `IsAllowed()` now matches both `Allowed` and `Passed`.
- `parseRetryAfter` supports both RFC-7231 delta-seconds and HTTP-date.

### Migration
- If you previously checked `IsRateLimited(err)`, switch to
  `result.IsRateLimited()` plus `time.Sleep(time.Duration(result.RetryAfterMs)
  * time.Millisecond)` before retrying.
- If you previously caught a `*PalveronError` for `Blocked`, switch to
  `result.Decision == palveron.Blocked` or `result.IsBlocked()`.

## [1.0.0] — 2026-05-18

### Added
- Initial public release of `github.com/palveron/sdk-go` (tagged `v1.0.0`)
- `palveron.NewClient` constructor for the synchronous client
- `Verify`, `Check`, `VerifyFile` for the core governance call
- `ListPolicies` and `Health` endpoints
- Multi-modal attachments (image, audio, video, document, code)
- MCP / agentic `RequestContext` propagation
- Retry with exponential backoff + jitter (configurable, max 30 s)
- Circuit breaker (5 failures → open → 30 s cooldown → half-open)
- Typed errors: `AuthenticationError`, `RateLimitError`, `ValidationError`,
  `TimeoutError`, `CircuitOpenError`
- Custom headers + on-premise base URL support
- Zero external dependencies — stdlib only

### Security
- API keys transmitted via `Authorization` header only (never in URL or body)
- TLS verification enabled by default
- No secrets logged or exposed in error messages
