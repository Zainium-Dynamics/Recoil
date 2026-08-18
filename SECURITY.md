# Security Policy

## Supported Versions

Recoil is currently in active development (Milestone 1 of 5). The `main` branch represents the current development state. Security fixes are applied to the latest commit on `main` and included in the next release tag.

| Version | Supported |
|---|---|
| main (development) | Yes |
| < v1.0.0 | No — pre-release only |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.** Public disclosure before a fix is available puts all Recoil users at risk.

### Contact

Email: **alizain.arch@gmail.com**
Subject line: `[RECOIL SECURITY] <brief description>`

### What to Include

- A clear description of the vulnerability and the affected component
- The version or commit where the issue was found
- Steps to reproduce or a proof-of-concept
- Your assessment of the impact and severity
- Whether you prefer credit or want to remain anonymous

### Response Timeline

**48 hours** — acknowledgement of receipt

**7 days** — initial assessment and proposed disclosure timeline

**30 days** — target for patch release for cryptographic vulnerabilities

**60 days** — target for patch release for other components

If a fix requires more time than the proposed timeline, the maintainer will communicate this before the deadline passes.

---

## Disclosure Policy

Recoil follows coordinated disclosure. Once a fix is ready and released, the vulnerability is documented in the release notes and in this file's changelog section below. Reporters who wish to be credited are named unless they prefer anonymity.

The maintainer will not request an embargo longer than 90 days except in exceptional circumstances agreed upon with the reporter.

---

## Security Architecture Summary

The following summarises the security-relevant design decisions in Recoil. Reviewers evaluating the cryptographic implementation should consult `ARCHITECTURE.md` for full technical detail.

**Key derivation** uses PBKDF2-HMAC-SHA512 at 600,000 iterations (Milestones 1–2) and Argon2id with 64 MiB memory cost (Milestone 3+).

**Encryption** uses AES-256-GCM with fresh OsRng 96-bit nonces per operation. Nonce reuse is structurally impossible.

**Key material** is stored in `Zeroize + ZeroizeOnDrop` protected memory. Key bytes are cleared on drop and do not appear in log output, error messages, or debug representations.

**Authentication failure** returns the same `AuthFailed` error regardless of whether the cause is a wrong password, tampered ciphertext, truncated data, or nonce-length violation. No diagnostic detail is disclosed.

**Brute-force protection** applies three tiers of exponential back-off using wall-clock timestamps stored on disk. Lockout state survives reboots.

**Filesystem immutability** uses `FS_IMMUTABLE_FL` via `ioctl(FS_IOC_SETFLAGS)` as an anti-accident and anti-user-space-malware layer, combined with eBPF `ioctl` monitoring (Milestone 4) for privileged bypass protection.

**Audit log integrity** uses a Merkle tree with HMAC-protected root (Milestone 3) that detects any retroactive modification including truncation-and-rechain attacks.

---

## Known Limitations

**Milestone 1 and 2 only:** The current build uses PBKDF2-HMAC-SHA512 rather than the memory-hard Argon2id algorithm. PBKDF2 at 600,000 iterations provides reasonable protection against CPU-based attacks but is more vulnerable to GPU-accelerated brute-force than Argon2id. Argon2id is implemented in Milestone 3.

**Milestone 1 and 2 only:** The eBPF daemon that enforces master password authentication before permitting `chattr -i` removal is not yet implemented. Until Milestone 4, the `FS_IMMUTABLE_FL` protection can be cleared by a root process holding `CAP_LINUX_IMMUTABLE`. The flag still provides robust protection against the primary threat model (accidental scripts and user-space malware in standard privilege contexts).

**All milestones:** Recovery from a permanently hard-locked vault requires the `RECOIL_RECOVERY=1` environment variable bypass. This mechanism is documented, auditable, and cannot be activated without physical access to the system and the ability to set environment variables as root.

---

## Acknowledged Vulnerabilities

*None at this time.*

---

**Contact:** alizain.arch@gmail.com
**Repository:** https://github.com/darkgineer/recoil
