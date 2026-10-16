# CLAUDE.md

## 🤖 Welcome, Claude

This repository uses **`AGENTS.md`** as the single source of truth for:

* Coding conventions (naming, formatting, commenting, testing)
* Contribution workflows (branch prefixes, commit message style, PR templates)
* Release, CI, and dependency‑management policies
* Security reporting and governance links

> **TL;DR:** **Read `AGENTS.md` first.**
> All technical or procedural questions are answered there.

### Quick Checklist for Claude

1. **Study `AGENTS.md`**
   Make sure every automated change or suggestion respects those rules.
2. **Follow branch‑prefix and commit‑message standards**
   They drive Mergify auto‑labeling and CI gates.
3. **Never tag releases**
4. **Pass CI**
   Run `go fmt`, `goimports`, `go vet`, `staticcheck`, and `golangci‑lint` locally before opening a PR.

If you encounter conflicting guidance elsewhere, `AGENTS.md` wins.
Questions or ambiguities? Open a discussion or ping a maintainer instead of guessing.

Happy hacking!

---

## About This Project

`go-bouncer` is a small Go SDK for the **Bouncer email-verification API v1.1**: real-time
verification (`Verify`), batch-sync (`VerifyBatchSync`, partial results), the credit balance
(`Credits`) and the native asynchronous batch workflow behind `client.Batches()` (`Create`, `Status`,
`Results`, `Download`, `Finish`, `Delete`), plus one bounded helper, `Wait`, which only polls
`Status`. It is a library, not an application: there is no binary, no CLI, and no runtime
configuration file.

- Module: `github.com/mrz1836/go-bouncer` (package `bouncer`, one flat package)
- Go version: 1.26 only (go.mod `go 1.26`; CI runs 1.26.x)
- Runtime dependencies: none (`testify` is used only by tests and `internal/testutil`)

**Invariants that changes must preserve:**
- **No runtime dependencies.** Library code imports only the standard library, and never `log`,
  `os`, `unsafe`, `encoding/csv`, `net/http/httputil` or `net/http/httptrace`. The `depguard` and
  `forbidigo` linters enforce this.
- **Exactly one HTTP attempt per call.** No retries, redirects, hedging, fallbacks, hidden polling
  or follow-on calls. Every request is built so the standard library cannot resend it: `GetBody`
  stays nil, and a GET or DELETE carries a non-nil empty body that is not `http.NoBody` (Finish, a
  bodyless POST, is the documented exception). The SDK's own transport is HTTP/1.1 only. Nothing
  paid, state-changing or destructive (`Verify`, `VerifyBatchSync`, `Create`, `Finish`, `Delete`)
  ever happens unless the caller calls that method.
- **The API key reaches only the provider or loopback.** It travels only in the `x-api-key` header.
  There is no general base URL option; `WithTestBaseURL` accepts only `https` on `127.0.0.0/8` or
  `[::1]`. Redirects are refused and their `Location` stripped. The key lives only inside function
  values the `Client` holds.
- **No values in errors.** `Error()` holds only the operation, kind, HTTP status, envelope status,
  JSON field paths and a fixed transport class: never the key, addresses, names, URLs, header
  values, bodies or provider text. Provider messages on errors are opt-in
  (`WithProviderDiagnostics`).
- **No logging, globals (other than sentinel errors) or `init`, no background goroutines, and no
  environment reads** in SDK code. The SDK's transport has no proxy; callers inject an
  `*http.Client` for one.
- **Downloads are streamed byte for byte.** The SDK never parses CSV, never closes or flushes the
  caller's writer and never rewrites line endings. `Results` streams with memory bounded by one
  record.
- **Unit tests stay offline.** The live tests (`live_internal_test.go`, `live` build tag) can make
  billable calls and are run only by the owner, by hand, after approval. Never run them, and never
  run the `examples/` programs against the provider.
- **Synthetic data only.** Fixtures are written from scratch to the documented shape; never copy
  provider examples or commit real responses. Addresses use `example.com`, `example.net`,
  `example.org` or `.invalid` only. CSV fixtures are Go string literals, never `.csv` files, because
  `.gitattributes` would rewrite their line endings.
