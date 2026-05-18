# Changelog

All notable changes to the Palveron Go SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
