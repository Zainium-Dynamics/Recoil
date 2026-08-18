# Recoil — Architecture Reference
## Technical Design Document for Developers and Reviewers

**Version:** 1.0 — May 2026
**Author:** Ali Zain <alizain.arch@gmail.com>
**License:** GNU General Public License v3.0

---

## 1. Module Structure

```
recoil/
├── Cargo.toml               All dependencies exact-pinned (= syntax)
└── src/
    ├── main.rs              Tokio entry point — calls cli::run()
    ├── lib.rs               Crate root — declares all six top-level modules
    ├── error.rs             19-variant RecoilError + Result<T> alias
    │
    ├── utils/
    │   ├── mod.rs
    │   ├── constants.rs     All project-wide strings, paths, thresholds
    │   ├── os_detect.rs     19-distro detection via /etc/os-release
    │   ├── fs_detect.rs     statfs(2) filesystem detection + LinkStrategy
    │   └── logging.rs       tracing-subscriber init via RECOIL_LOG env var
    │
    ├── security/
    │   └── mod.rs           PBKDF2 KDF, AES-256-GCM, MasterKey, LockState
    │
    ├── config/
    │   └── mod.rs           RecoilConfig schema + ConfigManager persistence
    │
    ├── shadow/              [Milestone 2 — stubs in Milestone 1]
    │   ├── mod.rs
    │   ├── immutable.rs     ioctl(FS_IOC_SETFLAGS) management
    │   ├── linking.rs       FICLONE reflink / hard link / copy fallback
    │   └── scanner.rs       walkdir root filesystem scanner
    │
    └── cli/
        ├── mod.rs           Clap top-level router
        ├── display.rs       All terminal output formatting functions
        ├── auth.rs          Centralised password verification + rate limiter
        └── commands/
            ├── mod.rs
            ├── setup.rs     [ACTIVE] Full implementation
            ├── status.rs    [ACTIVE] Full implementation
            ├── history.rs   [ACTIVE] Full implementation
            ├── restore.rs   [ACTIVE] Full implementation
            ├── unlock.rs    [ACTIVE] Full implementation
            ├── verify.rs    [Milestone 2 stub]
            ├── provenance.rs [Milestone 4 stub]
            ├── vault.rs     [Milestone 3 stub]
            ├── daemon.rs    [Milestone 5 stub]
            └── tui.rs       [Milestone 5 stub]
```

---

## 2. Dependency Decisions

All dependencies are exact-pinned using `=` version syntax. This is a permanent architectural decision, not a preference. The reason is that `argon2 0.5.x` transitively pulls `base64ct 1.8.x` which requires `edition = "2024"`, incompatible with the Rust 1.75 minimum supported version. Exact pinning guarantees that `cargo update` cannot silently break the build on older toolchains.

`serde_json` is used for all internal encrypted structures rather than TOML. The `toml_edit` crate pulls `indexmap 2.x` which also requires `edition = "2024"`. Since all configuration is AES-256-GCM encrypted on disk, the serialisation format is invisible to users — JSON is the correct choice.

PBKDF2-HMAC-SHA512 at 600,000 iterations is used for key derivation in Milestones 1 and 2. Argon2id (64 MiB, 3 iterations, 4-way parallelism) is planned for Milestone 3 once toolchain compatibility is confirmed. The two algorithms share an identical interface in the codebase; the migration is transparent to users.

---

## 3. Cryptographic Design

### 3.1 Key Derivation

```
password + salt (32 B, OsRng) ──► PBKDF2-HMAC-SHA512 (600,000 iters) ──► MasterKey [u8; 32]
```

`MasterKey` wraps `[u8; 32]` and implements `Zeroize + ZeroizeOnDrop`. When the value is dropped, the 32 key bytes are overwritten with zeros. The `Debug` implementation prints `MasterKey([REDACTED])` to prevent accidental exposure in log output or panic messages.

### 3.2 Encryption

On-disk format: `nonce (12 B) || ciphertext + GCM_tag`

Every `encrypt()` call generates a fresh 12-byte nonce from `OsRng`. Nonce reuse is structurally impossible — there is no path in the code where a nonce is reused.

`decrypt()` returns `Err(RecoilError::AuthFailed)` for every failure mode: wrong key, tampered ciphertext, truncated data, nonce-length violations. No diagnostic detail is included. An attacker cannot distinguish between these cases from the error response.

### 3.3 Configuration On-Disk Layout

```
[  salt (32 B)  ][  nonce (12 B)  ][  ciphertext + GCM_tag  ]
```

The salt is prepended outside the encrypted envelope. This allows `ConfigManager::load()` to extract the salt, derive the key, and attempt decryption in a single read without any additional stored metadata.

### 3.4 Rate Limiter

All state is wall-clock Unix seconds stored in a JSON file at `<base>/.lock_state`. The state survives reboots — an attacker cannot reset the lockout by power-cycling the device.

| Tier | Trigger | Lockout |
|---|---|---|
| Tier 1 | 3 consecutive failures | 20 minutes |
| Tier 2 | 15 failures in any rolling 60-minute window | 3 hours |
| Tier 3 | 50 failures in any rolling 24-hour window | Permanent hard lock |

The hard lock requires manual administrator intervention. The `RECOIL_RECOVERY=1` environment variable provides an offline bypass for legitimate administrators — documented, auditable, and explicitly scoped.

---

## 4. Shadow Directory Structure

```
/<root>/
└── .recoil-<distro>/          Hidden (dot prefix). 700 root:root.
    ├── root-mirror/           Complete root filesystem mirror
    │   ├── bin/   ← REAL DIR  Never a symlink — unconditionally recoverable
    │   ├── sbin/  ← REAL DIR
    │   ├── lib/   ← REAL DIR
    │   ├── lib64/ ← REAL DIR
    │   ├── usr/   boot/   etc/   root/
    │   ├── home/  var/    opt/   srv/
    │
    ├── versions/              Point-in-time versioned snapshots
    │
    ├── recoil-b/
    │   └── recoil-ctl         Static musl binary — zero runtime dependencies
    │
    ├── vault/                 AES-256-GCM encrypted deleted-file storage
    ├── logs/                  Merkle HMAC-chained append-only audit trail
    ├── db/                    AES-256-GCM forensic chronology database
    ├── .config                AES-256-GCM encrypted Recoil configuration
    └── .lock_state            Persistent rate-limiter state (JSON)
```

### Why bin/sbin/lib/lib64 are real directories

On modern Linux systems using the merged-/usr layout, `/bin`, `/sbin`, `/lib`, and `/lib64` are symbolic links pointing into `/usr`. If the mirror preserved these as symlinks, a recovery scenario where `/usr` is damaged or deleted would leave the mirror unusable — a symlink pointing into a damaged target is worthless for recovery.

Recoil creates these four paths as independent physical directories in the mirror regardless of their type on the live system. This adds negligible space overhead (hard links are used for the files inside them) and makes recovery unconditionally reliable.

---

## 5. Immutability Architecture

### Layer 1 — chattr +i (VFS layer)

`FS_IMMUTABLE_FL` is applied via `ioctl(FS_IOC_SETFLAGS)`. Once set, `unlink()`, `rename()`, `open(O_WRONLY)`, and `truncate()` return `EPERM` for any process that does not hold `CAP_LINUX_IMMUTABLE`. A standard `sudo` session does not grant this capability unless the sudoers configuration explicitly permits it.

This layer defends against: accidental recursive scripts, user-space malware in standard privilege contexts, and automated attack tooling targeting well-known paths.

### Layer 2 — eBPF ioctl monitoring (Milestone 4)

A BPF program attached to the `sys_ioctl` kernel tracepoint filters for `FS_IOC_SETFLAGS` calls targeting the shadow directory tree. When detected, the operation is suspended and the user must provide the master password before it is permitted.

This layer defends against: root-level processes holding `CAP_LINUX_IMMUTABLE`, automated malware specifically targeting the immutable flag, and any other privileged bypass that `chattr +i` alone cannot prevent.

**Together these two layers provide defence in depth.** The VFS flag defeats casual and automated bypass. The eBPF layer defeats the deliberate privileged bypass that a flat `chattr +i` cannot address.

---

## 6. Interception Architecture (Milestone 4)

### LD_PRELOAD Layer

- Rust `cdylib` shared library injected via `LD_PRELOAD`
- Hooks: `unlink`, `unlinkat`, `rename`, `open(O_TRUNC)`, `truncate`, `ftruncate`
- Mechanism: `dlsym(RTLD_NEXT)` to locate original glibc functions
- Correctness requirements: re-entrant safety via thread-local recursion guard, signal handler compatibility via `SA_RESTART`, setuid binary edge-case handling, zero latency for safe operations
- Coverage: all dynamically linked processes

### eBPF Layer

- BPF programs attached to `sys_unlinkat`, `sys_openat`, `sys_renameat2` via `libbpf`
- Fires at VFS layer inside kernel before syscall completes
- BPF ring buffer for high-throughput event delivery to userspace daemon
- Coverage: all processes including statically compiled binaries

### Why Both Layers Are Necessary

LD_PRELOAD covers the common case (dynamically linked programs) with lower latency. eBPF covers all remaining cases (statically compiled Go/Rust binaries, io_uring operations, any process that bypasses the dynamic linker). Every destructive filesystem syscall on Linux passes through at least one of the two layers.

---

## 7. Vault Architecture (Milestone 3)

### Content-Addressed Storage

Each intercepted file is stored at:
```
vault/<sha256_prefix_4>/<sha256_full>/content.enc
vault/<sha256_prefix_4>/<sha256_full>/meta.json.enc
```

The content hash prefix provides O(1) lookup without a database. Per-file keys are derived from the master key combined with the content hash, making per-file key reuse structurally impossible.

### Asynchronous Worker Pipeline

```
Interception hook
       │
       ▼
  Bounded MPSC channel   ← configurable buffer size
       │
       ▼
  Worker pool            ← one task per CPU core by default
  ┌────────────────┐
  │ AES-256-GCM    │
  │ BLAKE3 checksum│
  │ Merkle leaf    │
  │ fsync          │
  └────────────────┘
```

The interception hook enqueues path + metadata and returns immediately. The calling process sees zero blocking at any deletion volume. Under maximum deletion load the channel buffers work and workers process it at full CPU throughput.

---

## 8. Audit Log Architecture (Milestone 3)

Each event is a Merkle tree leaf node. Internal nodes are `SHA-256(left || right)`. The root summarises the entire audit history and is stored HMAC-protected inside the shadow layer, with the HMAC key derived from the master password.

On every `recoil verify` call, the root is recomputed from the full leaf set and compared against the stored root. Any modification — including the truncation-and-rechain attack that defeats a flat HMAC chain — produces a different root and triggers vault lockdown.

`chattr +a` (append-only flag) is additionally applied to the audit log file at the filesystem level as a second independent tamper-resistance layer.

---

## 9. Self-Relocation

When installed via `cargo install recoil`, the binary lands at `~/.cargo/bin/recoil` — a user home directory, writable without root. On the first `sudo recoil setup`, Recoil:

1. Detects it is running from a user-writable path
2. Copies itself to `/usr/local/bin/recoil`
3. Deploys the static `recoil-ctl` binary to `/.recoil-<distro>/recoil-b/`
4. Removes `~/.cargo/bin/recoil`

After setup, no Recoil binary exists in any user-writable path. Milestone 3 adds an enforcement check that refuses execution from `~/.cargo/` on an already-initialised system.

---

## 10. Locked Architectural Decisions

The following decisions are permanently locked. They must not be changed without a corresponding migration path and a version increment.

**RECOIL_HEADER constant** — The application header string is defined once in `constants.rs` and referenced everywhere. It never appears as a string literal in command code.

**= version pinning** — All `Cargo.toml` dependencies use exact `=` pinning. No dependency may be updated to a version that transitively requires `edition = "2024"` until the project formally raises its MSRV beyond 1.82.

**AuthFailed carries no detail** — Every code path that handles authentication, decryption, or MAC verification returns the same `AuthFailed` variant with no diagnostic detail.

**Shadow directory dot-prefix** — Shadow directory names always begin with `.recoil-` followed by the distribution name. This naming convention is permanent.

**Real directories for bin/sbin/lib/lib64** — These four paths are always created as physical directories in the mirror, never as symlinks. This is documented in `MIRROR_PATHS` in `constants.rs`.

**One file per command** — Each `recoil <command>` implementation lives in its own dedicated source file under `src/cli/commands/`. No exceptions.

---

**Document:** ARCHITECTURE.md · May 2026
**Author:** Ali Zain · alizain.arch@gmail.com
