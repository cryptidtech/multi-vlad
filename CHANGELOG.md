# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- `examples/lamport.rs`: a `no_run` example that builds and verifies a Vlad with a Lamport-SHA3-256 ephemeral key pair. The example is `no_run` because the published `multi-key` crate does not yet include the Lamport signing view. When the Lamport view ships in `multi-key`, the example will compile and run unchanged.

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

[0.1.0]: https://github.com/cryptidtech/multi-vlad/releases/tag/v0.1.0