Before creating any git commit on Go source files, run `golangci-lint run ./...` and fix all reported issues.
If golangci-lint is not installed, install it with `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`.
Do not use `--no-verify` or skip the lint step. If lint errors are found, fix them before committing.
This applies to all commits — feature, fix, refactor, test, and CI changes alike.
