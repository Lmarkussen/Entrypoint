# Contributing

EntryPoint changes must stay conservative, safe, and reproducible.

## Documentation Rule

Any code change that adds, removes, or changes behavior must update README.md and docs/ where relevant.

This applies to:

- New modules
- Flag changes
- Validation-logic changes
- Output-format changes
- Safety-model changes

## Module Changes

When adding or changing a module:

- Document the validation proof logic
- Document false-positive guardrails
- Keep validation read-only in safe mode
- Add or update tests for parsing, filtering, or classification where behavior changes
