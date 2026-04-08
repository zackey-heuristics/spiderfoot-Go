# Agent Division of Labor

This document defines the roles and workflow for AI agents collaborating on SpiderFoot-Go.

## Roles

### Claude Code (Architect / Orchestrator)

**Responsibilities:**
- Analyze the existing Python codebase to understand architecture and behavior
- Create detailed implementation plans for each phase/task
- Review Codex output and decide whether to accept, revise, or reject
- Run verification steps (`go build`, `go test -race`, `golangci-lint run`)
- Create git commits and pull requests
- Manage the issue tracker and project workflow
- Make architectural decisions and resolve design trade-offs

**Does NOT:**
- Implement large code changes directly (delegates to Codex)
- Skip planning — always produce a written plan before implementation

### Codex (Implementer / Reviewer)

**Responsibilities:**
- Implement code based on Claude Code's plan
- Write unit tests alongside implementation
- Perform adversarial review of its own or Claude Code's code
- Flag potential issues: security, performance, correctness, style
- Suggest improvements during review

**Receives from Claude Code:**
- A clear task description with file paths, interfaces, and expected behavior
- Verification steps to run after implementation

## Workflow

```
┌─────────────┐     plan      ┌─────────────┐
│ Claude Code  │─────────────▶│    User      │
│ (Architect)  │◀─────────────│  (Approval)  │
└──────┬───────┘   approve    └─────────────┘
       │
       │ task spec
       ▼
┌─────────────┐
│   Codex      │
│ (Implement)  │
└──────┬───────┘
       │
       │ code output
       ▼
┌─────────────┐     pass      ┌─────────────┐
│ Claude Code  │─────────────▶│   Commit     │
│ (Verify)     │              └─────────────┘
└──────┬───────┘
       │ fail
       ▼
┌─────────────┐
│   Codex      │
│ (Adv.Review) │──▶ fix issues ──▶ re-verify
└─────────────┘
```

### Step-by-step

1. **Plan** — Claude Code creates a detailed implementation plan in Plan mode.
2. **Approve** — User reviews and approves the plan.
3. **Implement** — Claude Code delegates implementation to Codex with a precise task spec.
4. **Verify** — Claude Code runs `go build ./...`, `go test -race -count=1 ./...`, `golangci-lint run ./...`.
5. **Adversarial Review** — Claude Code delegates review to Codex:
   - "Review this code for correctness, security, performance, and Go idioms. List every issue found."
6. **Iterate** — If issues are found, fix and re-verify (repeat steps 3-5).
7. **Commit** — Once all checks pass and review is clean, Claude Code creates the commit.

## Task Spec Template (Claude Code → Codex)

When delegating work to Codex, use this format:

```
## Task: <short title>

### Context
<Why this task exists, what it achieves>

### Files to create/modify
- `path/to/file.go` — <what this file should contain>

### Interface contract
<Go type definitions, function signatures, expected behavior>

### Tests
- <List of test cases to implement>

### Verification
Run after implementation:
1. go build ./...
2. go test -race -count=1 ./...
3. golangci-lint run ./...
```

## Phase 2 Notes

Phase 2 involves HTML templates, JavaScript, and CSS alongside Go code.
- Codex implementation tasks may include writing `.html`, `.js`, and `.css` files.
- Claude Code should verify templates render correctly in addition to Go build/test.
- Use the Codex plugin (`/codex:adversarial-review`) for design-level review.
- For large frontend tasks, Claude Code may implement directly if Codex sandbox limitations prevent file writes.

## Phase 3 Notes (Module Porting)

Phase 3 ports 234 Python modules to Go in numbered batches. Progress, conventions,
batch list, and environment quirks are tracked in
`.claude/plans/phase3-module-port-progress.md` — read this file before resuming.

- Each batch: implement modules → `go test -vet=off` → `gofmt -w` → commit
- Batches 0-14 (99 modules) are complete; next is Batch 15 (to be selected from remaining Python modules). The per-module API key convention is established — see "API Key Convention" in `.claude/plans/phase3-module-port-progress.md`. Note: module names must be single-word (no underscores) to survive `SF_MODULE_<MOD>_<KEY>` env-var split — e.g. `hybrid_analysis` was registered as `hybridanalysis`.
- Group similar regex extractors into shared files using the `contentExtractor`
  base type to avoid one-file-per-module bloat
- **Module dedup**: all HTTP/DNS-backed HandleEvents must use the shared
  `seenSet.begin(ctx, key)` primitive defined in `internal/modules/free_apis.go`.
  Pattern at HandleEvent entry:
  ```go
  if evt == nil || evt.Data == "" { return nil, nil }
  // Dedup key must include evt.Type so modules that watch multiple
  // type namespaces (IP_ADDRESS vs AFFILIATE_IPADDR, DOMAIN_NAME vs
  // INTERNET_NAME) don't drop one context after seeing the other.
  skip, finish, err := m.seen.begin(ctx, string(evt.Type)+":"+evt.Data)
  if err != nil { return nil, err }
  if skip { return nil, nil }
  committed := false
  defer func() { finish(committed) }()
  // IMPORTANT: set committed=true only AFTER json.Unmarshal success,
  // so a 200 with garbage body (rate-limit HTML, truncated JSON) does
  // not permanently suppress retries for this key.
  // ... do work ...
  // after a definitive upstream response (HTTP 200 / definitive DNS answer):
  committed = true
  ```
  Set `committed = true` only AFTER a definitive upstream response; leave it
  false on transient errors so the deferred `finish` releases the reservation
  and a later event can retry. Do NOT use `seen.add`/`seen.contains`/`seen.remove`
  directly — they no longer exist.
- This devcontainer cannot run `go vet` or `golangci-lint` (segfault / OOM) —
  use `gofmt -l` and `go test -vet=off` instead
- Always set `CGO_ENABLED=0 GOTOOLCHAIN=local` for build/test
- Claude Code may implement directly without Codex delegation when batches are
  routine pattern-matching modules — Codex review is more valuable for batches
  involving new shared infrastructure (API key system, tool wrappers)
- Codex sandbox has been intermittently broken in this environment
  (`bwrap: Failed to make / slave: Permission denied`). When `codex:rescue`
  returns a sandbox failure, fall back to direct implementation in Claude Code
  and still run `/codex:adversarial-review` afterwards — the review flow works
  even when implementation delegation does not.

## Adversarial Review Template (Claude Code → Codex)

```
## Adversarial Review

Review the following files for:
1. **Correctness** — logic errors, edge cases, nil pointer risks
2. **Security** — injection, path traversal, information leaks
3. **Performance** — unnecessary allocations, unbounded growth, missing context cancellation
4. **Go idioms** — error handling, naming, package organization
5. **Test coverage** — missing test cases, weak assertions

Files to review:
- <list of file paths>

For each issue found, report:
- File and line number
- Severity (critical / major / minor)
- Description and suggested fix
```
