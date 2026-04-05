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
