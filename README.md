# safe-npm

**See the package before it executes.** safe-npm is a local-first static security scanner for npm packages, written in Rust.

> v0.3 combines static source scanning, transitive dependency analysis and npm Registry intelligence **before package execution**.

## v0.3 highlights

- **Typosquatting heuristic:** flags names one edit away from a curated set of popular npm packages.
- **Registry trust signals:** deprecated versions, missing maintainers and extremely short version history.
- **Obfuscation-density heuristic:** detects unusually long/minified lines and dense hex/unicode escape usage.
- Registry signals are scored together with source-code findings across the full dependency tree.
- All v0.2 dependency-tree protections remain: SemVer resolution, cycle/dedup protection, bounded traversal and safe install policy.

## v0.2 foundation

- Recursive dependency-tree scanning with cycle/dedup protection.
- SemVer range resolution against the npm Registry.
- Configurable `--max-depth` (default 8) and `--max-packages` (default 500).
- Aggregated tree risk: the highest package risk becomes the installation policy risk.
- Unsupported git/file/http dependency sources are reported instead of silently trusted.
- Existing single-package `scan` mode remains available.
- `install` now scans the dependency tree before allowing npm to run.
- Lifecycle scripts stay disabled by default with `--ignore-scripts`.
- JSON tree report for CI/CD.
- Static landing page in `docs/`, ready for GitHub Pages.

## Install

```bash
cargo install --git https://github.com/mdnbras/safe-npm
```

## Usage

Single tarball:

```bash
safe-npm scan lodash
safe-npm scan lodash --json
```

Full production dependency tree:

```bash
safe-npm tree express
safe-npm tree express --max-depth 10 --max-packages 1000
safe-npm tree express --json
```

Scan the tree and install only if policy allows:

```bash
safe-npm install express
```

HIGH or CRITICAL anywhere in the scanned tree blocks installation. Overrides are explicit:

```bash
safe-npm install package --allow-risk
safe-npm install package --allow-scripts
```

## What is detected?

The current ruleset looks for lifecycle scripts, process/shell execution, dynamic code execution, credential/token access, environment access, network-capable code and encoded/obfuscated payload indicators.

| Severity | Weight |
|---|---:|
| LOW | 3 |
| MEDIUM | 10 |
| HIGH | 25 |
| CRITICAL | 40 |

Package score: LOW 0–19, MEDIUM 20–44, HIGH 45–74, CRITICAL 75–100.

## Architecture

```text
package@range
     |
     v
npm Registry metadata
     |
     +---- resolve SemVer ----+
     |                       |
     v                       v
download root .tgz       dependency ranges
     |                       |
     v                       +---- recursive queue
static scanner                        |
     |                                v
     +---------------------- scan dependency .tgz
                              |
                              v
                    deduplicate / prevent cycles
                              |
                              v
                    aggregate tree risk
                              |
                 +------------+-------------+
                 |                          |
              report                 install policy
                                      |
                             npm --ignore-scripts
```

## Landing page

The website source lives in `docs/`. A GitHub Pages workflow is included at `.github/workflows/pages.yml`.

If Pages is configured to use **GitHub Actions** as its source, pushes affecting `docs/` automatically deploy the site.

## Security boundaries

safe-npm v0.3 deliberately does not execute downloaded packages. Individual source files larger than 2 MiB are skipped. Tree traversal is bounded by depth and package count. Git, local-file and direct HTTP dependency sources are currently reported as unsupported rather than fetched.

The scanner is heuristic: **a finding is not proof of malware, and a clean report is not proof of safety.** Use safe-npm as one defense-in-depth layer alongside npm audit, provenance/signature verification, lockfiles, review and runtime isolation.

## Roadmap

- AST-based JavaScript/TypeScript analysis.
- Typosquatting and package-name similarity.
- Registry signature/provenance verification.
- Package age, maintainer and release-anomaly signals.
- Entropy/minification heuristics.
- Configurable policies and allowlists.
- SARIF / GitHub Code Scanning.
- Parallel downloads/scanning and metadata cache.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

## License

MIT
