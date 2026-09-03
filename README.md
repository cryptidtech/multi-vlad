[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)](https://cryptid.tech/)
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)](https://github.com/cryptidtech/provenance-specifications/)
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)](https://github.com/multiformats/multiformats/)

[![Build Status](https://github.com/cryptidtech/multi-vlad/actions/workflows/rust.yml/badge.svg)](https://github.com/cryptidtech/multi-vlad/actions)
[![License](https://img.shields.io/crates/l/multi-vlad?style=flat-square)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/multi-vlad?style=flat-square)](https://crates.io/crates/multi-vlad)
[![Documentation](https://docs.rs/multi-vlad/badge.svg?style=flat-square)](https://docs.rs/multi-vlad)

# multi-vlad

Verifiable Long-Lived Address (VLAD) implementation: a combined `Multisig` whose message holds the WASM first-lock bytecode and whose signature is by an ephemeral key pair.

A `Vlad` is a newtype over a combined `Multisig`. The `Multisig` message field holds the binary WASM of a first-lock script. The signature is over that script, signed by an ephemeral key pair. The `Vlad` validates that the inner `Multisig` is combined (non-empty message) and that the message begins with the `\0asm` WASM magic bytes.

The goal is to avoid the anti-pattern of using public keys as identifiers. Public keys are subject to compromise and rotation, so identifiers derived from key material become invalid when keys change. A `Vlad` replaces the public-key identifier with a random identifier (the signature bytes) plus a cryptographic commitment to a validation function (the WASM script).

This crate contains only the `Vlad` half of the former `bs-multicid` workspace crate. The `Cid` half lives in the standalone `multi-cid` crate. The split lets a downstream crate depend on only the type it needs: `multi-vlad` depends on `multi-key` and `multi-sig` but not on `multi-hash`, which was only required by `Cid`.

## Table of Contents

- [Features](#features)
- [Install](#install)
- [Usage](#usage)
- [Feature Flags](#feature-flags)
- [The Split from `bs-multicid`](#the-split-from-bs-multicid)
- [Testing](#testing)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Features

- `Vlad` newtype over a combined `Multisig`.
- Builder pattern for `Vlad` from a signing key and a WASM message.
- WASM validation: rejects messages that do not begin with the `\0asm` magic bytes.
- Combined-signature validation: rejects detached signatures (empty message).
- `verify()` against the signing key via `multi-key` and `multi-sig`.
- Multibase encoding via `multi-base` and `multi-util`. `EncodedVlad` detects the encoding on decode and always encodes to `Base32Lower`.
- Serde integration under the `serde` feature. Human-readable formats give a struct with a `multisig` field; binary formats give the raw bytes.
- DAG-CBOR support under the `dag_cbor` feature via `multi-cbor`.

## Install

Add this to your `Cargo.toml`:

```toml
[dependencies]
multi-vlad = "0.1"
```

MSRV: Rust 1.95 (required by `multi-key`).

## Usage

```rust
use multi_vlad::Builder;
use multi_key::EncodedMultikey;

let mk = EncodedMultikey::try_from(
    "fba2480260874657374206b657901012064e58adf88f85cbec6a0448a0803f9d28cf9231a7141be413f83cf6aa883cd04"
).unwrap().to_inner();
let msg = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]; // WASM magic + version

let vlad = Builder::default()
    .with_signing_key(&mk)
    .with_message(&msg)
    .try_build()
    .unwrap();

// verify the Vlad against the signing key
vlad.verify(&mk).unwrap();

// round-trip through bytes
let bytes: Vec<u8> = vlad.clone().into();
let decoded = multi_vlad::Vlad::try_from(&bytes[..]).unwrap();
assert_eq!(vlad, decoded);
```

## Feature Flags

| Feature | Default | Effect |
|---|---|---|
| `serde` | yes | Enables serde serialization for `Vlad`. |
| `dag_cbor` | yes | Enables CBOR support for `Vlad` via `multi-cbor`. |
| `xmss` | yes | Enables XMSS post-quantum signature support via `multi-key`. |

## Examples

- `examples/ed25519.rs` — Build and verify a Vlad with a random Ed25519 ephemeral key pair. Runnable:
  ```bash
  cargo run --example ed25519
  ```

- `examples/lamport_merkle.rs` — Build and verify a Vlad with a merkle-tree Lamport (`lamport-merkle-blake3-256`) post-quantum ephemeral key pair. This is the recommended ephemeral key type. The tree depth is 1, so the key holds exactly two one-time signatures: one for the Vlad and one for the first provenance-log entry. Merkle keys are stateful, so the example uses `Builder::try_build_advance` and shows the advanced key that the caller must persist. Runnable:
  ```bash
  cargo run --example lamport_merkle
  ```

- `examples/xmss.rs` — Build and verify a Vlad with an XMSS-SHA2_10_256 post-quantum ephemeral key pair. XMSS is a stateful hash-based scheme: a single key can sign a bounded number of messages (2^h for height h), which is necessary for a Vlad because the same ephemeral key must sign both the Vlad and the first provenance-log entry. Use this scheme when the same ephemeral key must sign more than two messages. Runnable:
  ```bash
  cargo run --example xmss
  ```

## The Split from `bs-multicid`

The former `bs-multicid` workspace crate contained two types: `Cid` and `Vlad`. These types do not import from each other. They have disjoint dependency sets:

- `Cid` needs `multi-hash` for the `Multihash` field.
- `Vlad` needs `multi-key` and `multi-sig` for the inner `Multisig`.

Splitting the crate lets a downstream crate depend on only the type it needs. For example, `wacc` needs `Cid` but not `Vlad`, so `wacc` does not pull in `multi-key` or `multi-sig`.

The `multi-vlad` crate is the `Vlad` half. The `multi-cid` crate is the `Cid` half. `Vlad` does not depend on `wacc` or `multi-hash`. The WASM is opaque bytes; the code validates it only by the `\0asm` magic header. The `Script` type lives in `provenance-log`, not `wacc`.

## Testing

```bash
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --all-features --no-deps
```

## Maintainers

- Dave Grantham <dwg@linuxprogrammer.org>

## Contribute

Pull requests go to the [`cryptidtech/multi-vlad`](https://github.com/cryptidtech/multi-vlad)
repository. Sign commits with GPG. Use Conventional Commits messages.

## License

Licensed under `Apache-2.0`.

See [`LICENSE`](LICENSE) for the full text.