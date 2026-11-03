# Repository Operating Notes

## Product
Describe in 2–4 sentences what this repository operates and who uses it.

## Durable invariants
List only constraints that should survive ordinary refactors: security boundaries, canonical identity/data rules, external contracts, or other expensive-to-reverse commitments.

## Work style
- Investigate relevant code and run the product before assuming the task language describes the correct implementation.
- Prefer coherent end-to-end ownership over narrowly local edits.
- Make reversible implementation decisions autonomously.
- Surface decisions that change product meaning, security/privacy boundaries, durable data contracts, or other consequential commitments.
- For interface changes, inspect the rendered result; passing tests alone is not completion.

## Context
Point to relevant `docs/` by topic. Read only what the task requires.

## Contracted work
Frozen implementation contracts live in `tasks/`.

For a contracted task, the committed contract defines the required observable outcome. Do not modify the task spec or its declared evidence while implementing it. The shared verifier lives outside the project repository and acts as the completion trust anchor.

Run:

```bash
python ~/code/_kernel/verify.py tasks/<task>.toml --repo . --base main --claim "<completion claim>"
```

A supported verifier result is completion evidence; it is not a substitute for product judgment during discovery.
