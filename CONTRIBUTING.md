# Contributing to safe-npm

Thanks for helping improve safe-npm. This project analyzes npm packages before installation, so changes to detection, scoring, dependency traversal and AI validation should be treated as security-sensitive.

## Development setup

Requirements:

- Rust stable
- Cargo
- Git
- Network access for tests that explicitly query external services

Clone and validate the project:

```bash
git clone https://github.com/mdnbras/safe-npm.git
cd safe-npm

cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

Do not add real API keys, npm tokens or other credentials to source code, fixtures, logs or commits.

## Making a change

Create a branch from `master` and keep the change focused.

```bash
git checkout master
git pull
git checkout -b feat/my-change
```

Prefer small commits with descriptive messages such as:

```text
feat: add contextual rule
fix: preserve finding on invalid AI response
test: cover network false positive
docs: document scanner behavior
```

## Detection rules

A new detection rule should include tests for both sides of the behavior:

1. code that should trigger the rule;
2. realistic benign code that must not trigger it.

Avoid broad text matches when a more specific API or behavior can be identified. A URL, identifier or import alone is not necessarily proof that a security-relevant action occurred.

When adding or changing a `Finding`, preserve the contextual fields used by v0.5:

- `evidence`
- `ai_validation`

Scoring changes should be tested against duplicate findings so repeated occurrences of one rule do not accidentally inflate package risk.

## AI validation

AI analysis is optional and must remain opt-in.

When changing `src/ai.rs`:

- never hard-code or print an API key;
- use `OPENAI_API_KEY` for runtime authentication;
- send only the context required for validation;
- handle network failures and malformed/truncated responses safely;
- preserve a finding when AI cannot confidently validate it;
- do not treat AI output as proof that a package is safe or malicious;
- consider API request count, latency and cost when changing the validation loop.

Tests should not require a real OpenAI API key. Isolate model-independent behavior so it can be tested locally.

## Dependency-tree changes

Keep traversal bounded. Changes must preserve:

- cycle and duplicate protection;
- `max_depth`;
- `max_packages`;
- no execution of downloaded package code;
- no lifecycle-script execution during scanning.

Unsupported dependency sources should be reported rather than silently trusted.

## Pull requests

Before opening a PR, run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

A PR should explain:

- what changed;
- why it is needed;
- how it was tested;
- whether detection, scoring, policy, AI behavior or privacy changed;
- examples of false positives/false negatives affected by the change.

CodeRabbit is configured in `.coderabbit.yaml` to automatically review non-draft pull requests. Address relevant review comments or explain the trade-off in the PR discussion.

## Documentation

Update `README.md`, `README-pt-BR.md` and/or `docs/` when user-visible behavior changes.

Examples based on package scans must be presented as calibration evidence, not as claims that a package is safe, vulnerable or malicious.

## Security issues

Do not open a public issue containing an undisclosed exploitable vulnerability, credential, token or sensitive package content. Use the repository owner's private security reporting channel when available.

## License

By contributing, you agree that your contribution is provided under the repository's MIT license.
