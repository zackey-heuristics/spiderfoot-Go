When writing or modifying JavaScript or TypeScript code, every exported function, class, method, and type MUST have a JSDoc comment.

Rules:
- Use `/** ... */` block comment syntax for all doc comments.
- Functions: include `@param {type} name - description` for each parameter and `@returns {type} description` for the return value.
- Classes: describe the purpose of the class. Document the constructor with `@param` tags.
- Methods: document as functions above. For overrides, at minimum add `@override`.
- TypeScript types/interfaces: add a `/** ... */` comment describing the purpose. Document non-obvious properties inline.
- Constants/variables: add a `/** ... */` comment when the purpose is not self-evident from the name.
- Use `@throws {ErrorType}` to document exceptions.
- Use `@example` blocks for non-trivial usage patterns.

If you are editing an existing file and encounter exported symbols without JSDoc comments, add them as part of your change.
