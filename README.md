# safe-npm

A fast, local-first static security scanner for npm packages, written in Rust.

**safe-npm downloads the package tarball from the npm registry and inspects it before npm executes the package.** It is designed as an additional supply-chain security layer, not as a replacement for `npm audit`, provenance verification, antivirus software, or human review.

## Why?

`npm audit` is primarily focused on known vulnerabilities in dependency trees. npm can also verify registry signatures/provenance and control install scripts. Those mechanisms are valuable, but they do not answer a different question:

> "Does the package I am about to install contain suspicious code patterns?"

safe-npm v0.1.0 starts answering that question without executing the package.

## Features

- Downloads package metadata and tarball directly from the npm registry.
- Does **not** run package code during scanning.
- Scans JavaScript, TypeScript and `package.json` files in-memory.
- Detects install lifecycle scripts: `preinstall`, `install`, `postinstall`, `prepare`.
- Detects indicators for:
  - process/shell execution;
  - dynamic code execution;
  - credential/token access;
  - environment-variable access;
  - network access;
  - encoded/obfuscated payloads.
- Produces a 0–100 risk score and LOW/MEDIUM/HIGH/CRITICAL classification.
- JSON output for CI/CD integration.
- `safe-npm install` blocks HIGH/CRITICAL packages by default.
- Lifecycle scripts remain disabled during installation unless explicitly allowed.

## Install from source

```bash
cargo install --git https://github.com/mdnbras/safe-npm
```

Or:

```bash
git clone https://github.com/mdnbras/safe-npm.git
cd safe-npm
cargo build --release
```

## Usage

Scan the latest version:

```bash
safe-npm scan lodash
```

Scan an exact version:

```bash
safe-npm scan express@5.1.0
safe-npm scan @scope/package@1.2.3
```

Machine-readable output:

```bash
safe-npm scan lodash --json
```

Scan and install:

```bash
safe-npm install lodash
```

By default, installation uses `npm install <package> --ignore-scripts`. To explicitly enable lifecycle scripts after reviewing the report:

```bash
safe-npm install some-package --allow-scripts
```

To override a HIGH/CRITICAL block:

```bash
safe-npm install some-package --allow-risk
```

## Risk model

| Finding | Weight |
|---|---:|
| LOW | 3 |
| MEDIUM | 10 |
| HIGH | 25 |
| CRITICAL | 40 |

Score classification: LOW 0–19, MEDIUM 20–44, HIGH 45–74, CRITICAL 75–100.

The score is a heuristic. A finding is **not proof of malware**, and a low score is **not proof of safety**. Legitimate packages can use process execution, networking, environment variables, or install scripts.

## Security model

safe-npm v0.1 intentionally favors a simple, auditable architecture:

```text
Package spec
    |
    v
npm Registry metadata
    |
    v
Download .tgz ----> no execution
    |
    v
In-memory tar.gz inspection
    |
    +--> package.json lifecycle analysis
    +--> source pattern rules
    |
    v
Findings + risk score
    |
    +--> scan: report only
    |
    +--> install: policy gate --> npm install --ignore-scripts
```

The scanner skips individual files larger than 2 MiB in v0.1 to bound memory use.

## Roadmap

- Dependency-tree scanning.
- Typosquatting/package-name heuristics.
- npm registry signature and provenance verification.
- Maintainer/package-age/release-anomaly signals.
- Entropy and minification/obfuscation heuristics.
- AST-based JavaScript/TypeScript analysis.
- Configurable policies and allowlists.
- SARIF output and GitHub Code Scanning integration.
- GitHub Actions and pre-commit/CI examples.
- Parallel scanning and local metadata cache.

## Development

```bash
cargo fmt --check
cargo test
cargo clippy -- -D warnings
```

## Important limitations

This project performs heuristic static analysis. It cannot guarantee that a package is safe, and malware may evade pattern-based detection. It also does not currently recursively inspect all transitive dependencies.

Use it as one layer in a defense-in-depth supply-chain security strategy.

## License

MIT
