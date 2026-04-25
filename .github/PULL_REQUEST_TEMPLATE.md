<!--
Use a closing keyword in the line below so the issue auto-closes on
merge: `Closes #N`, `Fixes #N`, or `Resolves #N`. Delete the line if
this PR doesn't correspond to an issue.
-->

Closes #

## Summary

<!-- What changed and why. One paragraph or a short bullet list. Avoid
restating the diff. -->

## Test plan

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test --locked`
- [ ] `cargo deny check`

<!--
For bug-fix PRs, also consider:

  ## Root cause
  A few sentences on what was actually wrong, not just the symptom.

  ## Fix
  The smallest change that addresses the root cause, and why it's
  correct. Mention invariants preserved (persist-before-send, safety,
  determinism) if relevant.

Delete this comment block when you're done.
-->
