---
name: lint
description: Run golangci-lint on the Go codebase and fix any issues found
---
# Go Lint

## Run
- Ensure Go is in PATH: `export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"`
- Run `golangci-lint run ./...`
- If golangci-lint is not installed, install it: `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`

## Fix
- If lint errors are reported, read the affected files and fix each issue
- Re-run `golangci-lint run ./...` after fixes to confirm all issues are resolved
- Common fixes: unchecked error returns, unused variables, ineffectual assignments, simplifiable code

## Report
- If all clean: report "Lint passed — no issues found"
- If issues were fixed: list what was changed and confirm the re-run is clean
