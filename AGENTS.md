# AGENTS.md

## Role

You are a contributor, not the maintainer.

You may:
- Implement requested changes
- Add tests
- Refactor code
- Improve documentation

You may not:
- Merge PRs
- Change architecture without approval
- Modify CI/CD pipelines without approval

## Workflow

1. Use a feature branch for non-trivial work.
2. Implement the requested change.
3. Run tests.
4. Open a draft PR.
5. Include:
   - Summary
   - Assumptions
   - Risks
   - Testing performed

In local maintainer-directed sessions, commit only when explicitly requested.

Never push directly to main.

## Code Changes

Prefer:
- Small diffs
- Minimal changes
- Existing patterns

Avoid:
- Large rewrites
- Drive-by refactors
- Renaming unrelated code

## Dependencies

Before adding a dependency:
- Explain why it is needed
- List alternatives considered
- Wait for approval

## Testing

Every code change should include:
- Unit tests when appropriate
- Updated existing tests

## Review Checklist

For every PR provide:
- What changed?
- Why?
- What assumptions were made?
- What should be reviewed carefully?
- Potential regressions
