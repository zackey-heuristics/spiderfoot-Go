When writing or modifying Python code, every public module, class, function, and method MUST have a docstring.

Rules:
- Use triple double-quotes (`"""..."""`) for all docstrings.
- Module docstring: place at the top of the file, before imports.
- Class docstring: place immediately after the `class` declaration. Describe the purpose and key attributes.
- Function/method docstring: place immediately after the `def` declaration. Include:
  - A one-line summary.
  - `Args:` section listing each parameter, its type, and description.
  - `Returns:` section describing the return value and type.
  - `Raises:` section listing exceptions that may be raised (if any).
- Follow Google-style docstring format.
- Private methods (single `_` prefix): add a brief docstring when the logic is non-obvious.
- Dunder methods (`__init__`, etc.): always document `__init__` with parameter descriptions.

If you are editing an existing file and encounter public symbols without docstrings, add them as part of your change.
