## Summary
<!-- What changed, and why? -->

## Reviewer focus areas
<!-- For large or complex changes, point reviewers to the parts that need careful attention.
     Examples: tricky logic, design choices, edge cases, performance, security, or specific files.
     If there are no special focus areas, write "None". -->

- **Please focus on:**
- **Why these areas need attention:**
- **Suggested review order or files:**

## References for reviewers
<!-- Link any design docs, issue discussions, prior changes, specifications, or other context reviewers should read first. Write "None" if there are no references. -->

## Related issue
<!-- Use "Closes #<id>", or write "None". -->
Closes #

## Change type

- [ ] Bug fix
- [ ] Feature
- [ ] Refactor
- [ ] Documentation
- [ ] Maintenance

## Implementation
<!-- Briefly describe the approach and any notable tradeoffs. Note the behavior and ownership
     boundary changed, and any public API, configuration, wire-format, persistence, or security impact. -->

## Verification
<!-- What did you test? Include commands and relevant results. CI runs the same Make targets. -->
- [ ] Tests added or updated where needed (limits, cancellation, error paths, and fallback as well as success)
- [ ] `make check` passes (format, license headers, strict Clippy, tests, doctests, rustdoc, live contract)
- [ ] `make test-sql` against disposable PostgreSQL and MySQL, or not applicable
- [ ] `make test-uso-kernel` on Linux for transfer/segmentation changes, or not applicable
- [ ] `make openapi-check` for HTTP route or schema changes, or not applicable
- [ ] Relevant checks pass
- [ ] Dependencies are verified (`cargo deny check`)
- [ ] Salt Install Verified, or not applicable

## Impact

- [ ] No known user-facing impact
- [ ] User-facing change (describe below)
- [ ] Database, API, configuration, or deployment impact (describe below)

<!-- Describe any impact checked above, including standard TFTP client behavior. -->

## Risks and rollout
<!-- Note risks, upgrade or migration steps, fallback or downgrade path, and monitoring needs.
     Write "None" if not applicable. -->

## Checklist

- [ ] The description explains the change and its purpose
- [ ] I reviewed my changes
- [ ] Documentation is updated where needed (README, CHANGELOG, UPGRADING, OpenAPI, config examples, rustdoc)
- [ ] I have removed temporary or debug code
- [ ] Commits are signed off (`git commit -s`, see CONTRIBUTING.md)
- [ ] No secrets, generated artifacts, private keys, internal data, or confidential material
