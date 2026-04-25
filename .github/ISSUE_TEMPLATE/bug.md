---
name: Bug
about: A reproducible defect — wrong behavior, panic, hang, or test flake.
title: "<area>: <one-line symptom>"
labels: ["bug"]
---

## What happened

<!-- The observed behavior. Logs, stack traces, failing assertions go
here verbatim. -->

## What you expected

<!-- The behavior you thought you'd see, and the invariant or doc that
led you to expect it. Cite path:line where helpful. -->

## Reproduction

<!-- Minimum steps to reproduce. Prefer a failing test or a one-liner
over prose. Include seeds for proptest/sim failures
(`proptest-regressions/` snippet, simulated time, node count). -->

```sh
# commands or test invocation
```

## Environment

- Rust toolchain: <output of `rustc --version` if locally reproduced>
- Git commit / branch:
- OS:

## Notes

<!-- Optional: hypotheses about root cause, related issues, anything you
already ruled out. -->
