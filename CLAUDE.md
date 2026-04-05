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

## Original Python Architecture (Reference)

The Python SpiderFoot consists of:
- `sf.py` — CLI entry point, starts CherryPy web server
- `sflib.py` — core SpiderFoot class (config, helpers, HTTP client)
- `sfscan.py` — scan runner
- `sfwebui.py` — web UI handlers
- `spiderfoot/db.py` — SQLite database layer
- `spiderfoot/event.py` — event type definitions
- `spiderfoot/plugin.py` — base module class
- `spiderfoot/target.py` — scan target abstraction
- `spiderfoot/correlation.py` — post-scan correlation
- `modules/sfp_*.py` — 234 OSINT modules
