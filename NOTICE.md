# Notices

`xpad2` control-plane code is distributed under GPL-3.0-or-later.

The release embeds independent, hash-locked executables and APKs as data and extracts them as
separate processes/files at runtime. Their exact binary and source identities are recorded in
`assets.lock.json` and `sources.lock.json`.

- `xpad2-ionstack-poc`: GPL-3.0-or-later aggregate with Apache-2.0-derived exploit portions;
  its upstream LICENSE and NOTICE are included in release packages.
- KernelSU late-load kernel module: GPL-2.0-only; `ksud-xpad2` and KernelSU Manager:
  GPL-3.0-only. Both license texts are included separately.
- `xpad-installer`: GPL-3.0-only; its upstream LICENSE is included.
- BoomInstaller: Apache-2.0; its LICENSE and fork attribution/modification notice are included.
- Rust dependencies retain their own licenses. The release package contains an inventory and
  the license files collected from the exact crate sources selected by `Cargo.lock`.

No production signing private key, encrypted password, recovery private key, GitHub credential,
ADB key, or pairing credential is included in this repository or any diagnostic package.
