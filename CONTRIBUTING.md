# Contributing to Recoil

Thank you for your interest in contributing to Recoil. This document explains the development standards, contribution process, and security reporting guidelines. Please read it before submitting any pull request.

---

## Before You Start

Recoil is safety-critical systems infrastructure. Errors in cryptographic code produce vulnerabilities rather than bugs. Errors in the LD_PRELOAD interception layer produce silent data corruption. Before contributing, understand that the bar for correctness here is higher than for typical software.

If you are planning a contribution that affects cryptographic code, the shadow layer architecture, the LD_PRELOAD interception design, or the command interface structure, please open a GitHub issue to discuss the approach before writing any code. This avoids wasted effort if the direction conflicts with locked architectural decisions.

---

## Environment Setup

```bash
git clone https://github.com/darkgineer/recoil
cd recoil
cargo build
cargo test --lib
```

**Minimum supported Rust version:** 1.75 stable.

Contributions must compile on Rust 1.75. If your change introduces a new dependency, you must verify that its complete transitive dependency tree does not pull in any crate requiring `edition = "2024"`. The `argon2` and `toml_edit` crates are the documented examples of why this matters.

```bash
cargo +1.75.0 build   # verify compatibility
cargo audit           # check for known vulnerabilities
```

---

## Code Standards

### Formatting and Linting

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

Both must pass without modification or suppression annotations before a pull request will be reviewed. If you add a clippy suppression, it must include an inline comment explaining exactly why the lint does not apply.

### Error Handling

All public functions must return `crate::error::Result<T>`. The use of `unwrap()` and `expect()` in non-test code is prohibited unless the operation is provably infallible, in which case an inline comment explaining the proof is required.

### Cryptographic Code Rules

These rules apply to any code touching key derivation, encryption, decryption, MAC computation, or random number generation. There are no exceptions.

Key material must be stored in `Zeroize`-protected types. It must never appear in log output, `Debug` output, error messages, or any location that could be written to disk in plaintext.

Nonces must be generated from `OsRng` for every operation. Fixed or seeded nonces are only acceptable in test code that is explicitly marked as using test vectors.

`decrypt()` and any function that verifies a MAC must return `RecoilError::AuthFailed` on failure with no diagnostic detail distinguishing failure modes.

New cryptographic primitives require explicit justification and an associated independent review before merging.

### Unsafe Code

`unsafe` blocks are permitted only where required by the platform API — specifically in `ioctl` wrappers and the LD_PRELOAD C ABI hooks. Every `unsafe` block must have a `// SAFETY:` comment that identifies the invariants being relied on and who is responsible for upholding them.

### Documentation

All public types, traits, and functions require `///` doc comments. Module-level `//!` comments are required for all `mod.rs` files and all files defining more than two public items.

---

## Testing Requirements

All contributions must include tests. The test suite must pass completely — no pre-existing test may begin failing as a result of your change.

Unit tests go in a `#[cfg(test)] mod tests` block at the bottom of the relevant source file. Integration tests that require filesystem access or root privileges go under `tests/`. Tests that require root privileges must include a guard that silently returns when `!is_root()`, allowing the CI environment to run the full suite as a non-root user.

```rust
#[test]
fn test_requiring_root() {
    if !crate::utils::os_detect::is_root() { return; }
    // ... test body
}
```

---

## Commit Message Format

Follow Conventional Commits: `<type>(<scope>): <description>`

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `security`

Examples:
```
feat(shadow): implement set_immutable_recursive with contents-first ordering
fix(security): correct PBKDF2 salt extraction in ConfigManager::load
security(crypto): use OsRng for all nonce generation in AES-GCM pipeline
test(config): add roundtrip test for RecoilConfig with all milestone flags
docs(arch): document immutability layer design in ARCHITECTURE.md
```

---

## Pull Request Process

1. Fork the repository and create a branch from `main`
2. Make your changes following the standards above
3. Run `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test --lib`, and `cargo audit`
4. All must pass before opening a PR
5. Write a clear PR description explaining what the change does, why it is needed, and which milestone it belongs to
6. If the change introduces a new dependency, explain the toolchain compatibility analysis
7. If the change touches cryptographic code, explain the design choices

Pull requests are reviewed by the project maintainer. Review focuses on correctness, safety, consistency with the project's established patterns, and completeness of tests and documentation. Feedback is provided within seven days for PRs that pass the initial CI check.

---

## Reporting Security Vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

Send an encrypted email to `alizain.arch@gmail.com` with the subject line `[RECOIL SECURITY] <brief description>`. Include:

- A description of the vulnerability
- The affected component and version range
- A proof-of-concept or reproduction case if available
- Your assessment of the potential impact

The project maintainer will acknowledge within 48 hours and respond with an assessment and proposed disclosure timeline within seven days.

Vulnerabilities in cryptographic components are highest priority and will be addressed with an expedited patch release.

---

## Locked Decisions — Do Not Propose Changes To

The following are permanently locked architectural decisions. Pull requests that change them will be closed without review. If you believe a locked decision is wrong, open an issue to discuss it rather than submitting a PR.

- The `=` version pinning convention in `Cargo.toml`
- The `AuthFailed` error variant carrying no diagnostic detail
- The dot-prefixed shadow directory naming convention
- The one-file-per-command convention under `src/cli/commands/`
- The use of real physical directories for `bin/`, `sbin/`, `lib/`, `lib64/` in the mirror
- The `RECOIL_HEADER` constant as the single source of truth for the application header string

---

## Code of Conduct

Contributions are evaluated on technical merit. Engage professionally and respectfully. The project maintainer reserves the right to close contributions without review for behaviour that is disrespectful, dishonest, or harmful to the project or its contributors.

---

**Ali Zain · alizain.arch@gmail.com · https://github.com/darkgineer/recoil**
