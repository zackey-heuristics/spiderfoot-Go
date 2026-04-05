After completing any Go code implementation (new feature, bug fix, refactor), run the following checks in order before presenting results to the user:
1. `go build ./...` — verify compilation
2. `go test -race -count=1 ./...` — verify all tests pass
3. `golangci-lint run ./...` — verify no lint errors

If any step fails, fix the issue and re-run from step 1. Do not skip steps.
When delegating implementation to Codex, include these verification steps in the task instructions.
