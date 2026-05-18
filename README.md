# palveron sdk-go

Official Go SDK for the **Palveron AI Governance Gateway** — policy enforcement, trace verification, and blockchain-anchored audit trails for every AI interaction.

[![Go Reference](https://pkg.go.dev/badge/github.com/palveron/sdk-go.svg)](https://pkg.go.dev/github.com/palveron/sdk-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/palveron/sdk-go?style=flat-square)](https://goreportcard.com/report/github.com/palveron/sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Documentation](https://img.shields.io/badge/docs-palveron.com-5A67D8?style=flat-square)](https://docs.palveron.com/sdks)

---

Every AI interaction your Go service makes — governed, audited, and optionally anchored to the blockchain. Stdlib-only client.

- **Zero dependencies** — pure stdlib, ships in your binary at ~50 kB
- **Multi-modal** — text, images, audio, documents, code
- **Enterprise-grade** — retry with exponential backoff, circuit breaker, typed errors
- **On-prem ready** — point to any Palveron gateway endpoint

## Installation

```bash
go get github.com/palveron/sdk-go@v1.0.0
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    palveron "github.com/palveron/sdk-go"
)

func main() {
    client := palveron.NewClient(os.Getenv("PALVERON_API_KEY"))

    result, err := client.Verify(context.Background(), &palveron.VerifyRequest{
        Prompt: "Transfer $50,000 to account DE89370400440532013000",
    })
    if err != nil {
        log.Fatal(err)
    }

    if result.Decision == palveron.Blocked {
        log.Fatalf("Blocked by policy: %s", result.Reason)
    }

    // Always use result.Output instead of the raw prompt so downstream
    // LLMs never see PII / secrets the gateway redacted.
    fmt.Println(result.Output, result.TraceID)
}
```

## Features

- **Policy enforcement** — every prompt routed through your active guardrails before it reaches an LLM
- **Trace verification** — every decision logged with an integrity hash for tamper detection
- **Multi-modal attachments** — file helpers with auto MIME detection
- **Agentic / MCP context** — pass `RequestContext` so the audit trail captures the tool chain
- **Blockchain attestation** — high-severity traces anchored to Flare for cryptographic audit trails

## Requirements

- Go **1.21 or newer**
- No third-party runtime dependencies

## Links

- **Documentation** — [docs.palveron.com/sdks](https://docs.palveron.com/sdks)
- **Dashboard** — [palveron.com](https://palveron.com)
- **Support** — [hello@palveron.com](mailto:hello@palveron.com)
- **GitHub** — [palveron/sdk-go](https://github.com/palveron/sdk-go)
- **GoDoc** — [pkg.go.dev/github.com/palveron/sdk-go](https://pkg.go.dev/github.com/palveron/sdk-go)
- **Changelog** — [CHANGELOG.md](https://github.com/palveron/sdk-go/blob/main/CHANGELOG.md)

## License

[MIT](./LICENSE) — Copyright © 2026 Palveron.
