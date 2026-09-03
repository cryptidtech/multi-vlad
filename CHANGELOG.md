# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-01

### Added

- `Builder::try_build_advance` and `Builder::try_build_advance_encoded` for stateful signature schemes. They sign the WASM first-lock script with `SignView::sign_advance` and return the Vlad (or encoded Vlad) AND the advanced `Multikey`. The caller must persist the advanced key so the consumed one-time slot is never reused. The advanced key verifies the Vlad exactly like the original key (the merkle root does not change on advance). Plain `try_build`/`try_build_encoded` are unchanged and keep working for stateless keys (Ed25519, XMSS).
- `examples/lamport_merkle.rs` — build and verify a Vlad with a merkle-tree Lamport `lamport-merkle-blake3-256` ephemeral key at depth 1 (two one-time leaves: one for the Vlad, one for the first provenance-log entry), using `try_build_advance`.
- Three tests covering the merkle flow: sign/verify with both keys plus state introspection, tree exhaustion after two signatures (and the `UnsupportedAlgorithm` error from the stateless path), and rejection of a tampered depth attribute.

### Changed

- Updated dependencies: `multi-codec` 1.2 → 1.3, `multi-key` 1.1 → 1.2, `multi-sig` 1.2 → 1.3.
- Raised `rust-version` from 1.95 to 1.96 (required by `multi-key` 1.2 / `lamport_signature_plus` 0.5.0) and updated the CI MSRV job to 1.96.
- `examples/xmss.rs` doc comment updated: one-time Lamport cannot sign a Vlad, but merkle-tree Lamport can.
- README updated: `lamport-merkle-blake3-256` at depth 1 documented as the recommended ephemeral key type.

### Notes

- Merkle-tree Lamport keys (`LamportMerkle*Priv`) reject `Builder::try_build` by design: `SignView::sign` errors with `UnsupportedAlgorithm` and directs the caller to `try_build_advance`, which returns the advanced key state for persistence.

## [0.1.2] - 2026-08-18

### Changed

- `multi-base`, `multi-codec`, `multi-key`, `multi-sig`, `multi-trait`, and `multi-util` dependencies repointed from the local `bettersign` workspace `bs-*` packages to their published crates.io versions (`multi-base` 1.0, `multi-codec` 1.2, `multi-key` 1.1, `multi-sig` 1.2, `multi-trait` 1.0, `multi-util` 1.1). The crate no longer depends on a local checkout of the `bettersign` workspace.
- `proptest` dev-dependency bumped from 1.4 to 1.11.
- MSRV raised to 1.95 (required by `multi-key`). The `Verify MSRV` CI job now installs Rust 1.95.0.

## [0.1.1] - 2026-08-17

### Added

- `xmss` cargo feature (default). Enables XMSS post-quantum signature support via `multi-key`. A Vlad is created by signing the WASM first-lock script with an ephemeral key, and the same key is later used to sign the first provenance-log entry, so the key must support at least two signatures. XMSS-SHA2_10_256 (h=10) can sign up to 1024 messages per key, which is sufficient.
- `examples/xmss.rs`: a runnable example that builds and verifies a Vlad with a random XMSS-SHA2_10_256 ephemeral key pair.

### Removed

- `examples/lamport.rs` and the `lamport` cargo feature. Lamport keys are one-time (one signature per key) and cannot be used for a Vlad, which requires at least two signatures from the same ephemeral key (the Vlad plus the first plog entry).

### Changed

- `multi-key` dependency repointed to the local `../multi-key` crate (v1.1.0) which includes the XMSS signing view. `multi-sig` repointed to the local `../multi-sig` crate (v1.2.0) which includes the XMSS dispatch arms.

## [0.1.0] - 2026-08-13

### Added

- Initial standalone release of `multi-vlad` on crates.io.
- `Vlad`, `EncodedVlad`, the `Builder`, and `VladError`. Re-exported from the crate root.
- `Vlad::new(multisig)` constructor for callers that build a `Multisig` directly (e.g. via a signing view) rather than through the `Builder`.
- `Vlad::wasm()` accessor as an alias for `Vlad::message()`, named for the plog use case.
- `serde` cargo feature (default). Human-readable formats give a struct with a `multisig` field; binary formats give the raw bytes.
- `dag_cbor` cargo feature (default). Enables CBOR support for `Vlad` via `multi-cbor`.
- `[lints.clippy]` config in `Cargo.toml` with `pedantic`, `nursery`, and `cargo` groups.
- `examples/ed25519.rs`: a runnable example that builds and verifies a Vlad with a random Ed25519 ephemeral key pair.

### Changed

- Extracted from the `bs-multicid` workspace crate (`bettersign/crates/multicid/src/vlad.rs` and the `VladError` portion of `error.rs`). The crate is renamed from `bs-multicid` to `multi-vlad`. All `use bs_multicid::...` references now use `use multi_vlad::...`.
- The `Cid` type and its dependencies (`multi-hash`) are removed. `Cid` lives in the standalone `multi-cid` crate. The `Error` enum no longer has `Multihash`, `Cid`, or `CidError` variants. The `CidError` enum is removed.
- The `Error::kind()` method no longer returns `"Multihash"`, `"Cid"`, `"Multikey"`, `"Multisig"`, or `"Vlad"` for the removed variants.
- The `serde` module no longer has `Serialize`/`Deserialize` impls for `Cid`. The `serde` tests for `Cid` are removed.
- The `repository` field points at `https://github.com/cryptidtech/multi-vlad.git`.
- The MSRV is declared as 1.87 (required by `multi-key`).

### Changed

- Made `validate_inner` public as `Vlad::validate`. A verifier can now validate a decoded Vlad (combined signature + WASM magic) without needing to verify against a signing key. The serde `Deserialize` impl and `TryDecodeFrom` impl call `validate` instead of the former `validate_inner`.
- Added `Vlad::wasm()` as an alias for `Vlad::message()`. This names the accessor for the plog use case: the plog `Log` builder calls `vlad.wasm()` to seed `first_lock = Script::Bin(root_key, vlad.wasm())`.
- Improved docs on `Vlad::verify`, `Vlad::multisig`, `Vlad::message`, and `Vlad::wasm` to document the plog verification flow: extract the WASM first-lock script, verify the signature over the WASM against the signing key, and run the WASM through the wacc VM to authorize the genesis entry.
- Added a `test_plog_verification_flow` test that demonstrates the full plog verification usage pattern: validate, extract WASM, verify against the signing key, round-trip through bytes, and re-verify.

### Fixed

- Adapted to the published crates.io APIs of `multi-codec`, `multi-sig`, and `multi-trait`. The published `Codec` and `Multisig` types impl `From<*> for Vec<u8>` and `TryDecodeFrom` but not `EncodeIntoBuffer`. The `From<Vlad> for Vec<u8>` impl now builds the byte representation via `extend_from_slice` on `Vec<u8>` obtained from `From<Codec>` and `From<Multisig>`, instead of delegating to `EncodeIntoBuffer` on `Codec` and `Multisig`.

### Notes

- The `multi-base`, `multi-codec`, `multi-key`, `multi-sig`, `multi-trait`, and `multi-util` dependencies use the published crates.io versions. `multi-vlad` does not declare `multi-hash` as a dependency; it appears transitively via `multi-key`.

[0.2.0]: https://github.com/cryptidtech/multi-vlad/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/cryptidtech/multi-vlad/releases/tag/v0.1.2
[0.1.1]: https://github.com/cryptidtech/multi-vlad/releases/tag/v0.1.1
[0.1.0]: https://github.com/cryptidtech/multi-vlad/releases/tag/v0.1.0