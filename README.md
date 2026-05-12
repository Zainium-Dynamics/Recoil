# Recoil
### Immutable System Safety Net, Chronology Engine & Integrated Vault for Linux

[![Rust](https://img.shields.io/badge/Rust-2021_Edition-000000?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL_v3-blue.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-blue)](https://kernel.org)
[![Phase 1](https://img.shields.io/badge/Phase_1-In_Development-yellow)]() 

Recoil is a Rust-native system safety layer for Linux. It creates a complete, kernel-immutable mirror of your root filesystem inside a hidden shadow directory, intercepts destructive terminal commands in real time, and maintains a forensic-quality record of every significant system change. When something goes wrong — an accidental `rm -rf`, a wrong `dd` target, a corrupted system path — Recoil brings it back.

Recoil also integrates Vaultion, a production-grade per-file AES-256-GCM encrypted vault, as a hardened subcomponent housed entirely within the shadow layer, isolated from the standard filesystem paths that automated attack tooling targets.

---

## How It Works

When you run `sudo recoil setup`, Recoil creates a hidden directory at your filesystem root named after your Linux distribution. On Debian it is `/.recoil-debian/`. On Ubuntu it is `/.recoil-ubuntu/`. On Zainium OS it is `/.recoil-zainium/`. The directory is invisible to `ls` by default. It contains a complete mirror of your root filesystem — every binary, library, configuration file, user directory, and OS-specific path — linked using hard links on ext4 or copy-on-write reflinks on Btrfs and XFS, consuming near-zero additional disk space.

The moment the mirror is populated, the entire shadow directory is locked with `chattr +i` — a kernel-level flag that makes `sudo rm -rf /.recoil-debian/` return `Operation not permitted`. The only way to unlock any part of it is through `recoil unlock`, which requires your master password.

After setup, a statically compiled recovery binary is placed at `/.recoil-<distro>/recoil-b/recoil-ctl`. This binary has zero runtime dependencies. If `/usr/bin`, `/lib`, and `/usr/lib` are all deleted, this binary is still executable and can restore your entire system.

---

## Shadow Directory Structure

```
/.recoil-linux/                 Hidden. chattr +i. Survives sudo rm -rf.
│
├── root-mirror/                 Complete root filesystem mirror
│   ├── bin/    (real directory — not a symlink)
│   ├── sbin/   (real directory — not a symlink)
│   ├── lib/    (real directory — not a symlink)
│   ├── lib64/  (real directory — not a symlink)
│   ├── usr/    boot/  etc/  root/  home/  var/  opt/  srv/
│   ├── overlayer/  styles/  zaisys/   (OS-specific paths)
│   └── (dev/ proc/ sys/ run/ tmp/ excluded — runtime only)
│
├── recoil-b/                    Protected binary storage
│   └── recoil-ctl               Static binary — works without /usr/bin
├── recoil-etc/                  Vaultion configuration (Phase 5+)
├── vault/                       Encrypted deleted-file storage (Phase 3+)
├── logs/                        Immutable audit trail (Phase 3+)
├── db/                          Chronology database (Phase 4+)
├── .config                      AES-256-GCM encrypted configuration
└── .lock_state                  Rate-limiter state
```

`bin/`, `sbin/`, `lib/`, and `lib64/` are real directories, not symlinks. On merged-/usr systems these are symlinks on the live filesystem. Recoil does not preserve this — a real directory in the shadow layer is independently recoverable regardless of the state of `/usr`.

---

## Distribution Support

| Distribution | Shadow Directory |
|---|---|
| Debian GNU/Linux | `/.recoil-debian/` |
| Ubuntu | `/.recoil-ubuntu/` |
| Arch Linux | `/.recoil-arch/` |
| Fedora Linux | `/.recoil-fedora/` |
| Kali Linux | `/.recoil-kali/` |
| openSUSE | `/.recoil-opensuse/` |
| Linux Mint | `/.recoil-mint/` |
| Zainium OS | `/.recoil-zainium/` |
| Generic Linux | `/.recoil-linux/` |

> **Missing your distribution?**
> Recoil's OS detection engine is designed to be highly extensible. Contributors are highly encouraged to add support for their favorite Linux-based operating systems. If you want to see your custom distro or a missing Linux flavor supported, feel free to open a Pull Request!

---

## Commands

Every command requires the master password. There is no session, no cached token.

```bash
# First-time setup — creates shadow layer, mirrors root, applies chattr +i
sudo recoil setup

# System and shadow layer status
recoil status

# Restore a file or directory from the vault
recoil restore ~/project/src/main.rs

# Restore as it existed at a specific point in time
recoil restore /etc/nginx --date "2026-05-10 14:00:00"

# Full system restoration from root-mirror (also works from recoil-ctl)
sudo recoil restore --system

# Emergency-restore a specific path from root-mirror
sudo recoil emergency-restore /usr/bin/python3

# Verify shadow layer integrity
recoil verify

# Unlock a specific shadow layer path (authenticated chattr -i)
sudo recoil unlock --path /.recoil-debian/vault/

# Browse system change history
recoil history
recoil history --search "nginx"

# View full lifecycle of any file or binary
recoil provenance /usr/bin/python3

# Per-file encryption vault (Vaultion integration, Phase 5+)
recoil vault encrypt ~/Documents/passport.pdf
recoil vault list
recoil vault decrypt passport.pdf.rvb

# Interactive terminal UI (Phase 5+)
recoil tui
```

---

## Command File Structure

Each command lives in its own source file under `src/cli/commands/`:

```
src/cli/commands/
├── setup.rs          recoil setup
├── status.rs         recoil status
├── restore.rs        recoil restore
├── history.rs        recoil history
├── verify.rs         recoil verify
├── unlock.rs         recoil unlock
├── emergency.rs      recoil emergency-restore
├── provenance.rs     recoil provenance
├── vault.rs          recoil vault
├── daemon.rs         recoil daemon
├── config.rs         recoil config
└── tui.rs            recoil tui
```

The static `recoil-ctl` binary in the shadow layer is the same `recoil` binary compiled with musl libc for zero runtime dependencies. It responds to the same commands.

---

## Installation

```bash
cargo install recoil
sudo recoil setup
```

On first setup, Recoil detects that it is running from `~/.cargo/bin/` and relocates itself to `/usr/local/bin/recoil`, placing the static `recoil-ctl` inside the shadow layer. The `~/.cargo/bin/recoil` copy is deleted. After setup, Recoil exists only in root-controlled locations.

---

## Project Status

| Phase | Focus | Status |
|---|---|---|
| Phase 1 | Foundation, CLI, cryptographic core | In Development |
| Phase 2 | Root mirror, shadow layer, chattr +i, recoil-ctl | Planned |
| Phase 3 | AES-256-GCM vault, Argon2id, audit log | Planned |
| Phase 4 | LD_PRELOAD interceptor, chronology engine | Planned |
| Phase 5 | Vaultion base integration, recovery, daemon | Planned |
| Phase 6 | Vaultion full, eBPF, Redox OS basic support | Planned |
| Phase 7 | Multi-distro validation, Redox strengthening, v1.0.0 | Planned |

---

## Related Projects

Recoil is developed alongside two other active projects under the same author.

**Zainium OS** is a custom Debian-based Linux distribution currently in its final stages of development, with an early public release arriving soon. It is driven by Rust-native system tooling at its core, featuring our custom-built Quantra architecture: Quantra-init (a memory-safe init system), Quantra-ramfs, and Quantra-net. Recoil will be shipped as a default-enabled system component in Zainium OS, making it the first Linux distribution to treat data loss as a preventable system failure rather than an expected user consequence.

**zex (Zainium-eXecutor)** is a next-generation, monolithic system executor and universal package manager for *ZainiumOS* written in memory-safe Rust. Replacing fragmented legacy utilities, zex unifies system commands, package management (sudo zex install <pkg>), and independent tool execution into a single, high-performance architectural blueprint. Like Recoil, zex aims to replace decades-old C infrastructure with modern, auditable, and secure engineering.

---

## Security Notes

The shadow layer is protected by `chattr +i` at the kernel level — not a permissions check, but a VFS-layer flag that returns `EPERM` to deletion and write attempts for all users including root. The `recoil-b/` and `recoil-etc/` directories are inside the hidden shadow layer rather than at `/usr/bin/` and `/etc/`, eliminating the attack surface that automated exploit tooling targets by convention. The known limitation of LD_PRELOAD interception — statically compiled binaries can bypass it — is addressed in Phase 6 with eBPF secondary interception.

---

## License

Copyright (C) 2026 Ali Zain `<alizain.arch@gmail.com>`

GNU General Public License v3.0 — see [LICENSE](LICENSE).
