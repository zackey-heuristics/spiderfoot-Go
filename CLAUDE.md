# SpiderFoot-Go — CLAUDE.md

This file provides context for AI assistants (Claude Code, Codex, etc.) working on this repository.

## Project Overview

SpiderFoot-Go is a full rewrite of [SpiderFoot](https://github.com/smicallef/spiderfoot) (Python) in Go.
The goal is a single, statically-compiled binary that runs on Linux, macOS, and Windows (amd64 + arm64).

Tracking issue: #1

## Repository Layout

```
cmd/spiderfoot/          # main entry point (CLI + web server)
internal/
  config/                # configuration loading (YAML/env/flags)
  event/                 # event types and event bus
  module/                # module interface + registry
  scan/                  # scan orchestrator (goroutine pool)
  db/                    # storage layer (SQLite via modernc.org/sqlite)
  webui/                 # HTTP handlers, REST API, embedded static assets
  correlation/           # post-scan correlation engine
modules/                 # concrete OSINT module implementations
static/                  # CSS, JS, images (embedded via go:embed)
templates/               # HTML templates (embedded via go:embed)
e2e/                     # end-to-end tests
docs/                    # architecture & flow documentation
```

## Build & Test

```bash
# Prerequisites: Go >= 1.24

# Build
go build -o spiderfoot ./cmd/spiderfoot

# Run all tests with race detection
go test -race -count=1 ./...

# Lint
golangci-lint run ./...

# E2E tests (requires built binary)
go test -tags=e2e -race -count=1 ./e2e/...
```

## Key Design Decisions

- **No CGo** — use `modernc.org/sqlite` (pure-Go SQLite) so cross-compilation works without a C toolchain.
- **`go:embed`** — static assets and HTML templates are embedded in the binary.
- **Module interface** — every OSINT module implements `module.Module`. Modules register themselves via `init()`.
- **Event bus** — modules communicate through a typed event bus (`event.Bus`). A scan pushes seed events; modules consume and produce events.
- **Dual output** — the web UI serves HTML for humans; every endpoint also supports `Accept: application/json` for AI agents and automation.
- **Structured logging** — use `log/slog` with JSON output by default.

## Coding Standards

- All exported symbols MUST have GoDoc comments (see `.claude/rules/doc-comments-go.md`).
- Run `go build`, `go test -race`, and `golangci-lint run` before presenting any implementation (see `.claude/rules/go-lint-after-implementation.md`).
- Run `golangci-lint run` before every commit (see `.claude/rules/go-lint-before-commit.md`).
- Follow the issue-first workflow (see `.claude/rules/issue-first-workflow.md`).

## Agent Workflow

See `AGENTS.md` for the division of labor between Claude Code and Codex.

## Useful Commands

```bash
# Check current Go module
go list -m

# See all packages
go list ./...

# Generate architecture docs
go doc ./...

# Run a specific test
go test -run TestName ./internal/event/...
```

## Phase Status

- **Phase 1** (DONE) — Core framework: event bus, module system, scan orchestrator, SQLite storage, REST API skeleton, CLI, CI
- **Phase 2** (DONE) — Full Web UI: browser-based scan creation/management/results
- **Phase 3** (IN PROGRESS) — Module porting: 99 / 234 modules ported (Batches 0-14 complete). Progress and conventions tracked in `.claude/plans/phase3-module-port-progress.md`. **Next**: Batch 15. See the "Session handoff" block at the top of that file for a resume prompt.
- **Phase 4** (TODO) — Correlation engine, advanced features

### Phase 3 Progress
- **Batch 0**: `internal/sflib/` shared utility package (HTTP, DNS, extract, HTML, SSL, country, ratelimit, toolexec)
- **Batch 1**: Core DNS — dns_brute, dns_commonsrv, dns_neighbor, dns_raw, dns_zonexfer, stor_stdout
- **Batch 2**: Network/SSL/WHOIS/Web — portscan_tcp, sslcert, whois, spider, webframework, webserver, pageinfo, strangeheaders
- **Batch 3**: Content text extractors — email, bitcoin, ethereum, creditcard, iban, phone, names, errors, binstring, hashes, base64, cookie
- **Batch 4**: Content/web/file — company, countryname, intfiles, junkfiles, webanalytics, pgp, similar, filemeta
- **Batch 5**: Public DNS Resolvers — adguard_dns, cleanbrowsing, cloudflaredns, comodo, opendns, quad9, yandexdns (shared `publicDNSResolver` generic)
- **Batch 6**: DNS/IP Blacklists — spamhaus, sorbs, spamcop, uceprotect, dronebl, surbl (shared `ipDNSBL` generic)
- **Batch 7**: Free APIs Part 1 — hackertarget, crt, certspotter, dnsdumpster, commoncrawl, archiveorg, bgpview, ripe, robtex
- **Batch 8**: Free APIs Part 2 — googlesearch, bingsearch, duckduckgo, sublist3r, stackoverflow, searchcode (googlesearch/bingsearch require API keys via opts and no-op gracefully without them; full API key wiring deferred to Batch 11+)
- **Batch 9**: Phishing/Reputation — phishtank, openphish, emergingthreats, threatcrowd, phishstats (shared `hostFeed` and `ipFeed` generics; feed download via `fetchOnce` helper with retry-on-failure semantics)
- **Batch 10**: Social/Username — social, accounts, github, twitter, flickr, keybase, gravatar, slideshare (`accounts` uses WhatsMyName dataset, capped to first 50 sites per username)
- **Batch 11**: Email/Phone Services — haveibeenpwned, hunter, clearbit, emailrep. First batch requiring API keys; establishes the API key convention (per-module prefixed opt keys like `hibp_api_key`, `SF_MODULE_<MOD>_<KEY>` env injection, `module.Meta.RequiresAPIKey` flag). Clearbit's Discover API is deprecated (2023) but the code path is faithfully ported.
- **Batch 12**: Major APIs Part 1 — shodan, virustotal, abuseipdb, censys, greynoise, ipinfo, securitytrails. 7 modules in `major_apis.go`. Exercises 4 distinct auth schemes (query param, custom header, Basic, Bearer). Censys uses a uid+secret pair (mirrors googlesearch's two-key pattern). AbuseIPDB lazy-loads the high-confidence blacklist once per scan and resets on `Finish()`.
- **Batch 13**: Major APIs Part 2 — riskiq, intelx, dehashed, leakix, threatfox, urlscan, xforce. 7 modules in `major_apis2.go`. Introduces shared `majorAPIFetchPOST` + `basicAuthHeader` helpers in `major_apis.go`. `threatfox` and `urlscan` are free/no-auth (Meta.RequiresAPIKey=false). Multi-credential modules (riskiq, dehashed, xforce) use two opt keys each.
- **Batch 14**: Security/Threat Intel — googlesafebrowsing, metadefender, hybridanalysis, openbugbounty. 4 modules in `security_intel.go`. `openbugbounty` is free (no auth, HTML scrape via regex). `hybrid_analysis` renamed to `hybridanalysis` (single-word) to comply with the `SF_MODULE_<MOD>_<KEY>` split-on-first-underscore constraint. Adds a local `postHybridForm` helper for `application/x-www-form-urlencoded` POSTs since `majorAPIFetchPOST` forces JSON content-type.
- **Dedup refactor**: All 27 HTTP-backed and 2 DNS-backed HandleEvents in Batch 1-10 now share a single `seenSet.begin` primitive (defined in `internal/modules/free_apis.go`) with atomic reserve, deferred `finish(committed bool)` callback, skip-on-in-flight semantics (no worker blocking), and a pointer-equality generation guard so stale handlers cannot corrupt a successor scan's state after `clear()`. Sequential events retry automatically after a transient HTTP/DNS failure via the commit/release mechanism. See Codex adversarial review history (rounds 1-10) summarized in the progress doc.
- **Next**: Batch 15 — see `.claude/plans/phase3-module-port-progress.md`.

### Phase 3 Build Notes (this devcontainer)
- `go vet` segfaults — always pass `-vet=off` to `go test`
- `golangci-lint` OOMs — use `gofmt -l` instead
- Always set `CGO_ENABLED=0 GOTOOLCHAIN=local` for `go build`/`go test`

## Phase 2: Web UI — Key Reference

The Python web UI (`sfwebui.py`, ~1900 lines) provides:

### Pages
- **New Scan** (`/newscan`) — target input, module selection (by use case / data type / individual), scan name
- **Scan List** (`/`) — dashboard with status badges, batch stop/delete/rerun/export
- **Scan Info** (`/scaninfo?id=<id>`) — results table, summary, correlations, network graph (Sigma.js), search, export
- **Settings** (`/opts`) — global config + per-module settings with API key indicators

### Frontend Stack (Python version)
- Bootstrap 3, jQuery, D3.js (charts), Sigma.js (graph), TableSorter, AlertifyJS
- Mako templates (server-side rendering)

### Go Implementation Approach
- `html/template` for server-side rendering (not Mako)
- Embed static assets via `go:embed` in `internal/webui/static/` and `internal/webui/templates/`
- Keep the same JS libraries (Bootstrap, jQuery, D3, Sigma) for frontend parity
- REST API endpoints return JSON; HTML pages use AJAX to fetch data
- Scan start/stop managed via API endpoints that interact with the scan orchestrator

## Original Python Architecture (Reference)

The Python SpiderFoot consists of:
- `sf.py` — CLI entry point, starts CherryPy web server
- `sflib.py` — core SpiderFoot class (config, helpers, HTTP client)
- `sfscan.py` — scan runner
- `sfwebui.py` — web UI handlers (~1900 lines, 40+ endpoints)
- `spiderfoot/db.py` — SQLite database layer
- `spiderfoot/event.py` — event type definitions
- `spiderfoot/plugin.py` — base module class
- `spiderfoot/target.py` — scan target abstraction
- `spiderfoot/correlation.py` — post-scan correlation
- `modules/sfp_*.py` — 234 OSINT modules
- `spiderfoot/templates/*.tmpl` — Mako HTML templates
- `spiderfoot/static/` — CSS, JS, images (Bootstrap, jQuery, D3, Sigma.js)
