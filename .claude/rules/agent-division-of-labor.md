Follow the workflow defined in AGENTS.md. This rule reinforces and supplements it.
For tasks beyond trivial changes (new features, multi-file refactors, bug fixes), use this workflow:
Claude Code creates the implementation plan in Plan mode, and Codex performs implementation and adversarial review.
Do not skip planning. Always produce a written plan and get user approval before implementation begins.
After Codex finishes implementation, run `make test` to verify correctness.
After tests pass, invoke Codex adversarial review before committing.
If adversarial review finds issues, fix them and re-run the tests before proceeding.
If Codex is unavailable, Claude Code may perform both implementation and self-review, but must still follow the plan-implement-test-review cycle.
