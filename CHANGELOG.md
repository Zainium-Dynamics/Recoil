# Changelog

All notable changes to Recoil are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] — Milestone 1 Active Development

### Added

**Foundation layer (Phase 0.5)**

- `src/error.rs` — Unified `RecoilError` enum with 19 variants covering all five project milestones. `AuthFailed` carries no diagnostic detail by design. `RateLimited { minutes }` carries remaining lockout time for accurate CLI display.

- `src/utils/constants.rs` — Single source of truth for `RECOIL_HEADER`, all shadow directory names, `MIN_FREE_BYTES` (64 MiB), `MIN_PASSWORD_LEN` (8), rate-limiter tier thresholds, and all mirror path names.

- `src/utils/os_detect.rs` — `/etc/os-release` parser with support for 19 named Linux distributions. `ID_LIKE` fallback chain for derivative distributions. Dot-prefixed shadow directory names for filesystem-level hiddenness.

- `src/utils/fs_detect.rs` — `statfs(2)` filesystem detection via magic number matching. `FilesystemType` with `link_strategy()`, `is_virtual()`, `cow_note()`. `same_filesystem()` for partition boundary detection. `available_bytes()` for disk space preflight.

- `src/security/mod.rs` — PBKDF2-HMAC-SHA512 at 600,000 iterations (OWASP 2024). `MasterKey` with `Zeroize + ZeroizeOnDrop`. AES-256-GCM with OsRng nonces. `LockState` three-tier rate limiter with reboot-proof wall-clock state. `password_strength()` advisory classifier.

- `src/config/mod.rs` — `RecoilConfig` schema with five milestone completion flags. `ConfigManager` with `bootstrap()` and `from_shadow()` constructors. AES-256-GCM encrypted JSON persistence with salt-prefixed on-disk layout. `load_lock_state()` and `save_lock_state()`.

- `src/shadow/` — Stub implementations of `immutable.rs`, `linking.rs`, `scanner.rs` with correct public signatures for Milestone 2.

- `src/cli/` — Clap 4.3 CLI skeleton with all ten commands declared and dispatched. All stubs present with correct argument types.

- GitHub Actions CI pipeline — `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test --lib`, `cargo build --release`, `cargo audit`.

- 25 unit tests passing across all foundation modules.

**CLI implementation (Phase 1.5)**

- `src/cli/display.rs` — Shared terminal output module. All formatting functions centralised: `print_header()`, `print_ok/err/warn/info()`, `prompt_password()`, `confirm_yn()`, `format_bytes()`, `format_ago()`, `print_table_header()`, `print_table_row()`.

- `src/cli/auth.rs` — Centralised `verify_master_password()` with full rate-limiter integration. Up to three password attempts. Correct "Attempts remaining" message on each failure. Tier 1 lockout activation. `RECOIL_RECOVERY=1` admin bypass.

- `src/cli/commands/setup.rs` — Full `recoil setup` implementation. Root check. Already-initialised guard. Disk space preflight. Password prompt with strength advisory and confirmation. PBKDF2 key derivation. Encrypted config persistence. Flags: `--reset`, `--force`, `--verbose`, `--no-daemon`.

- `src/cli/commands/status.rs` — Full `recoil status` implementation. Basic no-password view. `--verbose` authenticated view with statistics and last 5 actions. `--txt` file export with custom path error handling.

- `src/cli/commands/history.rs` — Full `recoil history` implementation. Authenticated table view. Flags: `--limit`, `--search`, `--date`, `--month`, `--type`, `--recovered`, `--in-recoil`, `--all`. `--stats` aggregate block. `--export` for csv/xlsx/json/txt.

- `src/cli/commands/restore.rs` — Full `recoil restore` implementation. Single file and directory restore. `--date` version restore. `--all` versions. `--dry-run`. `--system` root mirror restoration. File conflict prompt with three-option choice. All five error cases implemented.

- `src/cli/commands/unlock.rs` — Full `recoil unlock` implementation. Root check. Shadow path validation. Password authentication. `shadow::immutable::clear_immutable()` call. Re-lock reminder.

- `README.md`, `ARCHITECTURE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md` — Complete project documentation.

---

## Planned Releases

**v0.1.0** — Milestone 2 completion. Shadow layer operational. `sudo rm -rf /.recoil-debian/` returns `EPERM`. Atomic rollback working. `recoil verify` fully implemented.

**v0.2.0** — Milestone 3 completion. Vault encrypted with AES-256-GCM. Argon2id key derivation active. Async worker pipeline. Merkle tree audit log with tamper detection. NLnet proof-of-concept milestone.

**v0.3.0** — Milestone 4 completion. LD_PRELOAD and eBPF dual-layer interception. Smart system protection. Forensic chronology engine. `recoil history` and `recoil provenance` with real data.

**v0.4.0** — Milestone 5 completion. Full recovery engine. System daemon with systemd integration. Distribution packages. Redox OS initial port. Multi-distribution validation.

**v1.0.0** — Final release. All milestones complete. Validation report published. v1.0.0 tagged.

---

## Versioning Policy

Patch versions (0.1.x) correct defects and security issues that do not alter the command interface or the on-disk configuration format.

Minor versions (0.x.0) correspond to milestone completions and may introduce new commands or additive configuration schema fields. Breaking changes to the encrypted configuration format will always include a transparent migration path.

The major version increment from 0.x.x to 1.0.0 signifies production readiness as confirmed by the Milestone 5 multi-distribution validation.

---

**Project:** Recoil — Immutable System Safety Net for Linux
**Author:** Ali Zain · alizain.arch@gmail.com
**License:** GNU General Public License v3.0
