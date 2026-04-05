Before starting any feature or bug fix, run `gh issue list` to check for an existing open Issue.
If a similar proposal already exists (match by title keywords and labels), present it to the user and ask whether it is a duplicate before proceeding.
If no matching Issue exists, run `gh issue create` and include clear intent explaining why the change is being made.
Create the branch from the repository's default branch and name it `feature/<issue-number>-<short-slug>` for features or `fix/<issue-number>-<short-slug>` for bug fixes.
When merging to the default branch, always create a Pull Request.
Write the PR body to explain the intent and why this implementation approach was chosen, not just what changed.
Reference the Issue in the PR with `Closes #<number>` or `Fixes #<number>`.
