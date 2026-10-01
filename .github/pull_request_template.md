## Summary

<!-- Describe what this pull request changes and why it is needed. Keep it concise and provide enough context for reviewers. -->

## Related issue

<!-- Link the related issue when applicable. Example: Closes #123 -->

Closes #

## Type of change

<!-- Mark all that apply with an "x". -->

- [ ] Bug fix
- [ ] New feature
- [ ] Detection rule
- [ ] False-positive reduction
- [ ] AI / contextual analysis
- [ ] Dependency-tree / registry behavior
- [ ] Security hardening
- [ ] Refactoring
- [ ] CI / GitHub Actions
- [ ] Documentation
- [ ] Other

## What changed?

<!-- List the main implementation changes. -->

-

## How was it tested?

<!-- Describe the tests performed and include commands, scenarios or package calibration when relevant. -->

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

Additional validation:

-

## Security impact

<!--
safe-npm is a security scanner. Explain whether this PR changes detection,
scoring, package traversal, installation policy, secrets handling or trust decisions.
-->

- [ ] No security behavior changed
- [ ] Detection behavior changed
- [ ] Risk scoring changed
- [ ] Installation/blocking policy changed
- [ ] Package/dependency traversal changed
- [ ] Secret or credential handling changed

Details:

<!-- Explain any security trade-offs introduced by this PR. -->

## Detection impact

<!-- Complete this section when detection rules or heuristics change. -->

### Should trigger

<!-- Add representative malicious/suspicious examples that should be detected. -->

-

### Should NOT trigger

<!-- Add representative benign examples used to guard against false positives. -->

-

### False positives / false negatives

<!-- Describe the expected impact. Do not claim that a clean scan proves a package is safe. -->

-

## AI impact

<!-- Complete this section when AI/contextual validation changes. -->

- [ ] This PR does not change AI behavior
- [ ] Changes evidence sent to the AI validator
- [ ] Changes AI verdict handling
- [ ] Changes finding suppression/recalculation
- [ ] Changes API request volume, latency or cost
- [ ] Changes privacy/data handling

Details:

<!-- AI failures, malformed responses or uncertain verdicts must not silently make a finding safe. -->

## Evidence

<!-- Add relevant logs, JSON excerpts, screenshots, benchmark/calibration results or links to GitHub Actions runs. Remove secrets and sensitive source code first. -->

```text
Paste relevant evidence here
```

## Documentation

- [ ] No documentation update is required
- [ ] Updated `README.md`
- [ ] Updated `README-pt-BR.md`
- [ ] Updated GitHub Pages in `docs/`
- [ ] Updated `CONTRIBUTING.md`

## Checklist

- [ ] The change is focused and does not include unrelated modifications.
- [ ] I ran formatting, Clippy, tests and a release build locally or in CI.
- [ ] New/changed detection rules include positive and benign test cases.
- [ ] No API keys, tokens, credentials or sensitive data were committed.
- [ ] Downloaded npm package code is not executed during scanning.
- [ ] Lifecycle scripts remain disabled during safe scanning/install validation.
- [ ] AI uncertainty or failure preserves the security finding.
- [ ] User-visible behavior is documented.
- [ ] I reviewed the diff before submitting the PR.

## Reviewer notes

<!-- Anything reviewers or CodeRabbit should pay special attention to? -->

-
