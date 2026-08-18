# Recoil

**Immutable Root Filesystem Mirror · Atomic Rollback · Hybrid Kernel Interception · Cryptographic Provenance Tracking**

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org)
[![Status: Active Development](https://img.shields.io/badge/Status-Active%20Development-yellow.svg)]()
[![Phase: 1 of 5](https://img.shields.io/badge/Phase-1%20of%205-informational.svg)]()

---

Recoil is a Rust-native Linux security tool that permanently solves a problem that has existed for over thirty years: the complete absence of a production-grade, zero-configuration mechanism that protects users from accidental and irreversible data destruction in the Linux terminal, while simultaneously maintaining a forensic-quality, cryptographically verifiable record of every significant system change.

A single `sudo recoil setup` command activates full protection. No configuration files to edit. No services to manually configure. No ongoing maintenance required.

```
sudo recoil setup
```

```
Recoil v1.0.0 - Immutable System Safety Net for Linux

→ Starting setup wizard...

✓ Detected Distro       : Arch Linux (kernel 6.12.3-arch1-1)
✓ Shadow Layer          : .recoil-arch
✓ Filesystem            : btrfs (CoW supported)
✓ Available Space       : 284.7 GiB
✓ Root Protection       : Enabled (mirror layer ready)

...

✓ Recoil setup completed successfully!

Status: Protected ✓
```

---

## The Problem

The Linux terminal executes every command immediately, completely, and permanently. There is no built-in undo.

```bash
rm -rf ./project /          # misplaced space, deletes root filesystem
rm -rf $DIR/                # $DIR unset, becomes rm -rf /
dd if=/dev/zero of=/dev/sda # wrong block device, production volume gone
> /etc/nginx/nginx.conf     # redirect truncates config to zero bytes
```

These are not edge cases. They happen to experienced engineers on production systems under pressure, every single day. The gap between typing a destructive command and permanent data loss is measured in milliseconds.

Beyond accidental deletion, Linux has no systematic mechanism for tracking where a binary came from, how it was built, what it modified, or what process deleted it. When a system starts crashing after a week of changes, diagnosing the cause requires exactly this information.

Recoil was built to close both gaps permanently.

---

## How It Works

Recoil operates across four concurrent protection layers after a single setup command.

### Layer 1: Immutable Shadow Mirror

At setup, Recoil creates a complete copy of the root filesystem inside a hidden directory named after the detected distribution. On Debian it is `/.recoil-debian/`, on Arch `/.recoil-arch/`, on Ubuntu `/.recoil-ubuntu/`.

The directory is locked with `chattr +i`, a Linux kernel-level flag that makes the mirror immune to deletion even from root:

```bash
sudo rm -rf /.recoil-debian/
# rm: cannot remove '/.recoil-debian/': Operation not permitted
```

The copy uses hard links on ext4 or copy-on-write reflinks on Btrfs and XFS, consuming near-zero additional disk space. `bin/`, `sbin/`, `lib/`, and `lib64/` are always created as independent physical directories, never as symlinks, so recovery is reliable regardless of the state of `/usr`.

### Layer 2: Versioned Atomic Rollback

The shadow layer maintains multiple point-in-time versions of every tracked file, enabling atomic restoration to any historical state:

```bash
recoil rollback --last
recoil rollback --time "2 hours ago"
```

Rollback is all-or-nothing: if the operation cannot complete fully, the system is returned to its pre-restoration state rather than left partially modified.

### Layer 3: Hybrid Real-Time Interception

Two interception mechanisms run simultaneously:

**LD_PRELOAD layer**: A Rust `cdylib` shared library intercepts `unlink`, `rename`, `open(O_TRUNC)`, `truncate`, and other destructive calls for all dynamically linked processes. Zero observable latency for safe operations.

**eBPF layer**: BPF programs attached to `sys_unlinkat`, `sys_openat`, and `sys_renameat2` kernel tracepoints intercept the same calls at the VFS layer for *all* processes, including statically compiled Go and Rust binaries that bypass LD_PRELOAD entirely. The eBPF daemon also monitors `ioctl(FS_IOC_SETFLAGS)`, blocking any attempt to clear the shadow mirror's immutable flag without master password authentication.

Intercepted files are routed into an asynchronous AES-256-GCM encrypted vault via Tokio worker tasks. The calling process sees zero blocking at any deletion volume.

### Layer 4: Forensic Chronology Engine

Every significant system event is recorded with nanosecond-precision timestamps:

```bash
recoil provenance /usr/local/bin/sometool
```

```
Download    : wget https://example.com/tool.tar.gz
              SHA-256: a8f3c2d1...
              2026-05-15 09:14:22

Git Clone   : git clone https://github.com/org/sometool
              Commit: a3f2c91e (main)
              2026-05-15 09:31:45

Build       : cargo build --release
              rustc 1.78.0 - flags: --edition 2021
              2026-05-15 09:32:01

Install     : cp target/release/sometool /usr/local/bin/
              2026-05-15 09:32:18

Delete      : rm /usr/local/bin/sometool
              Vault: /.recoil-arch/vault/sometool_1621/
              2026-05-16 16:03:44
```

---

## Commands

```
recoil setup              First-time initialisation
recoil status             Protection status (basic: no password required)
recoil status --verbose   Full statistics (requires password)
recoil history            Complete system chronology
recoil restore <PATH>     Restore a file or directory
recoil rollback --last    Atomic rollback to previous state
recoil provenance <PATH>  Complete lifecycle of any file or binary
recoil verify             Shadow layer integrity check
recoil unlock --path <P>  Authenticated immutability removal
recoil vault encrypt      Per-file manual encryption
recoil audit export       Compliance-ready audit log export
```

---

## Installation

### From Cargo

```bash
cargo install recoil
sudo recoil setup
```

On first `sudo recoil setup`, Recoil detects it is running from `~/.cargo/bin/`, copies itself to `/usr/local/bin/recoil`, deploys the emergency recovery binary inside the shadow layer, and removes the user-space copy. After setup, Recoil exists only in root-controlled locations.

### From Source

```bash
git clone https://github.com/Zainium-Dynamics/Recoil
cd recoil
cargo build --release
sudo ./target/release/recoil setup
```

### Requirements

- Linux (any major distribution, see [Supported Distributions](#supported-distributions))
- Linux kernel 5.7 or later (required for the eBPF interception and immutable-flag enforcement layers)
- Rust 1.75 or later
- Root access for `recoil setup` and any command that modifies the shadow layer
- 64 MiB minimum free disk space

---

## Supported Distributions

| Distribution | Shadow Directory | Status |
|---|---|---|
| Debian GNU/Linux | `/.recoil-debian/` | Supported |
| Ubuntu | `/.recoil-ubuntu/` | Supported |
| Arch Linux | `/.recoil-arch/` | Supported |
| Fedora Linux | `/.recoil-fedora/` | Supported |
| Linux Mint | `/.recoil-mint/` | Supported |
| Kali Linux | `/.recoil-kali/` | Supported |
| Parrot OS | `/.recoil-parrot/` | Supported |
| openSUSE | `/.recoil-opensuse/` | Supported |
| AlmaLinux | `/.recoil-alma/` | Supported |
| Rocky Linux | `/.recoil-rocky/` | Supported |
| Pop!_OS | `/.recoil-pop/` | Supported |
| elementary OS | `/.recoil-elementary/` | Supported |
| Manjaro | `/.recoil-manjaro/` | Supported |
| Void Linux | `/.recoil-void/` | Supported |
| Alpine Linux | `/.recoil-alpine/` | Supported |
| Gentoo | `/.recoil-gentoo/` | Supported |
| CentOS | `/.recoil-centos/` | Supported |
| RHEL | `/.recoil-rhel/` | Supported |
| Derivative distros | `/.recoil-<base>/` | Via ID_LIKE fallback |
| Unknown | `/.recoil-linux/` | Generic fallback |

---

## Development Status

| Milestone | Focus | Status |
|---|---|---|
| Milestone 1 | Foundation and Cryptographic Core | 🟡 Active Development |
| Milestone 2 | Root Mirror, Versioning and Atomic Rollback | 🟡 Active Development |
| Milestone 3 | Vault, Argon2id, Async Workers, Merkle Audit | ⚪ Planned |
| Milestone 4 | Hybrid Interception (LD_PRELOAD + eBPF) and Provenance | ⚪ Planned |
| Milestone 5 | Recovery Engine, Daemon, Packaging, Redox OS, Release | ⚪ Planned |

---

## Security

All sensitive data is encrypted with AES-256-GCM. Fresh OsRng nonces are generated per operation. Nonce reuse is structurally impossible. Key material is stored in a `Zeroize + ZeroizeOnDrop` protected struct that clears from memory on drop.

Key derivation currently uses PBKDF2-HMAC-SHA512 at 600,000 iterations (OWASP 2024). Milestone 3 upgrades to Argon2id with 64 MiB memory cost, applied transparently with no user action required.

The brute-force rate limiter applies three tiers of exponential back-off using wall-clock timestamps stored on disk. Lockout state survives reboots. Tier 1: 20-minute lock after 3 failures. Tier 2: 3-hour lock after 15 failures in any rolling hour. Tier 3: permanent hard lock after 50 failures in any rolling 24 hours.

To report a security vulnerability, see [SECURITY.md](SECURITY.md).

---

## Emergency Recovery

When all standard system paths are damaged or deleted, the static `recoil-ctl` binary at `/.recoil-<distro>/recoil-b/recoil-ctl` provides emergency recovery. It is compiled against musl libc with zero runtime dependencies. It requires no dynamic linker, no shared libraries, and no working system paths.

```bash
/.recoil-debian/recoil-b/recoil-ctl restore --system
/.recoil-debian/recoil-b/recoil-ctl emergency-restore /usr/bin/python3
/.recoil-debian/recoil-b/recoil-ctl verify
/.recoil-debian/recoil-b/recoil-ctl status
```

Every command requires the master password.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development standards, the pull request process, and security vulnerability reporting.

---

## Related Projects

**Vaultion**: Per-file AES-256-GCM encrypted vault, the cryptographic foundation for Recoil's vault engine. [github.com/Zainium-Dynamics/vaultion](https://github.com/Zainium-Dynamics/vaultion)

---

## License

GNU General Public License v3.0, see [LICENSE](LICENSE) for the full text.
