When writing or modifying shell scripts (Bash, sh, Zsh), every script and every function MUST have a header comment.

Rules:
- Script header: at the top of the file (after the shebang), include a comment block describing the script's purpose, usage, and any required environment variables or arguments.
- Functions: place a comment block immediately before the function describing its purpose, arguments (`$1`, `$2`, etc.), expected output, and exit codes.
- Use `#` line comments. Keep them concise and aligned.
- For complex pipelines or non-obvious one-liners, add an inline comment explaining the intent.
- Document any global variables the script sets or depends on.

If you are editing an existing file and encounter functions without header comments, add them as part of your change.
