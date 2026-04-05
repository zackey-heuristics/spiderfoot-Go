---
name: commit-push
description: Review changes, create a conventional commit, and optionally push to remote
---
# Commit and Push

## Review
- Run `git status` to inspect all changed, staged, and untracked files
- Run `git diff --staged` and `git diff` to review both staged and unstaged changes
- Run `git log --oneline -5` to match recent commit message style

## Stage
- Stage only the files that are part of the logical change by explicit path
- Never use `git add -A` or `git add .`
- Do not stage files that likely contain secrets (.env, credentials.json, tokens, etc.) — warn the user if such files appear

## Commit
- Use conventional commit prefixes: `feat:`, `fix:`, `docs:`, `ci:`, `chore:`, `test:`
- Keep the message to one line, lowercase, imperative mood, under 72 characters
- If `$ARGUMENTS` is provided, treat it as guidance for the commit message
- Include the standard Co-Authored-By trailer for the current Claude model
- If the commit fails due to a pre-commit hook, fix the issue, re-stage, and create a NEW commit — never use --amend after a hook failure

## Push
- Ask the user whether they want to push to the remote
- If yes, push with `git push origin HEAD -u`
- Report the commit hash, branch name, and remote URL
