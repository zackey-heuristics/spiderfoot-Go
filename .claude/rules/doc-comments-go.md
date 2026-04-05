When writing or modifying Go code, every exported symbol (package, type, function, method, constant, variable) MUST have a GoDoc comment.

Rules:
- Package comments: place a `// Package <name> ...` comment directly above the `package` declaration. For multi-file packages, add it in `doc.go`.
- Exported functions/methods: `// FuncName does X ...` — start with the symbol name.
- Exported types: `// TypeName represents ...` — start with the type name.
- Exported constants/variables: `// ConstName is ...` — start with the symbol name.
- Unexported symbols: add a brief comment when the logic is non-obvious.
- Do not use `/* */` block comments for GoDoc; use `//` line comments.
- Run `go vet ./...` to catch missing doc comments on exported symbols.

If you are editing an existing file and encounter exported symbols without GoDoc comments, add them as part of your change.
