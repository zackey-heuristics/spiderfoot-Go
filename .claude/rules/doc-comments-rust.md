When writing or modifying Rust code, every public item (module, struct, enum, trait, function, method, constant, type alias) MUST have a rustdoc comment.

Rules:
- Use `///` line comments for item-level documentation (placed before the item).
- Use `//!` for module-level documentation (placed at the top of the file).
- Start with a one-line summary sentence.
- Use `# Examples` section with code blocks (` ```rust `) for non-trivial public APIs.
- Use `# Errors` section to describe when the function returns `Err`.
- Use `# Panics` section to describe conditions that cause a panic.
- Use `# Safety` section for `unsafe` functions explaining the invariants the caller must uphold.
- Document generic type parameters and lifetimes when their purpose is not obvious.
- Private items: add a brief `//` comment when the logic is non-obvious.
- Run `cargo doc --no-deps` to verify documentation builds without warnings.

If you are editing an existing file and encounter public items without rustdoc comments, add them as part of your change.
