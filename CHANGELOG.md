# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-26

### Added

- Genesis builders for the log-foot genesis: `Builder::try_build_genesis`, `try_build_genesis_advance`, `try_build_genesis_encoded`, and `try_build_genesis_advance_encoded`. A log-foot genesis authorizes the log's first entry under the VLAD first lock, and that first lock is the root key path's lock script of the genesis install, so the genesis Vlad's message must carry the multiproof verifier WASM component form. The shared duty checks the message before the signing state (a missing message reports the same `VladError::MissingMessage` the build path reports) and then builds through the matching plain builder: the advance variants return the advanced key state for persistence, exactly like `try_build_advance`.
- Two `VladError` variants. `ScriptForm` rejects a message that passes the `\0asm` magic check but is not the component form. `RootPattern` is reserved for the genesis first-lock duty: the genesis Vlad's message must carry the multiproof verifier component form of the root pattern. Both report the `"Vlad"` kind from `Error::kind()`.

### Changed

- Enforced the WASM component form for a Vlad message across `Vlad::validate` and every builder path (`try_build`, `try_build_advance`, and the encoded and genesis variants). A message must now carry the `\0asm` magic followed by the `0x0d` binary-component version byte; the former rule accepted any `\0asm` binary. A message shorter than the magic, or missing the magic, reports `VladError::InvalidWasm` as before. A message that stops after the magic, or that carries any other value in the version byte, reports `VladError::ScriptForm`. This breaks callers that pass a core-module form message (magic + `0x01`): rebuild the message from the component-form first-lock script and build the Vlad again. The decode and deserialize paths reject through the same check via `Vlad::validate`. The doc comments, README, and examples now use the component form.
- Updated the `multi-*` dependencies to their next-generation crates.io releases: `multi-codec` 1.6 → 2.0, `multi-key` 2.2 → 3.1, `multi-sig` 1.6 → 3.0, `multi-util` 1.2 → 2.0. The `Multikey` returned by the advance builders and consumed by `Vlad::verify` now carries the `multi-key` 3.x type, so downstream callers that name `Multikey` directly follow the major bumps.
- Dev-dependency bumps: `proptest` 1.11 → 1.12, `zeroize` 1 → 1.9.

### Removed

- The `dag_cbor` cargo feature and the optional `multi-cbor` dependency. `default` is now `["serde", "xmss"]`, and `multi-cbor` remains only as a dev-dependency. Callers that enabled `dag_cbor` to round-trip a Vlad through CBOR lose that path in this release.

### CI

- Rebuilt the workflow for the self-hosted multi-arch pool. An `msrv` job pinned to Rust 1.99.1 (`rust-version` itself stays 1.99) gates a Linux build matrix — x86_64-unknown-linux-gnu on stable, aarch64-unknown-linux-gnu and riscv64gc-unknown-linux-gnu on nightly, cross-tested on the x64 host through the image's target std, linkers, and qemu-user runners — and a new macOS build job covering aarch64-apple-darwin and x86_64-apple-darwin on the self-hosted macOS runner pool. Clippy keeps `--all-features` per target so the gated code stays lint-checked; the test jobs run an explicit feature list instead of `--all-features` to keep the cross-arch runs inside their budgets; rustfmt runs on the host stable toolchain.
- Removed the `pkcs1` 0.8.0-rc.4 pin steps from every job.
- Removed the coverage job and the Codecov upload.
- The Security Audit job now waits for the build jobs and skips `cargo install cargo-audit` when the binary is already present.
- Added `.github/dependabot.yml`: weekly cargo updates for direct and indirect dependencies, grouped by patch and minor bump type, labeled and with the `deps` commit prefix.

## [0.3.0] - 2026-10-08

### Changed

- Raised `rust-version` from 1.96 to 1.99 in line with the toolchain floor of the `multi-*` crates. The CI MSRV job installs Rust 1.99.0 and the README MSRV line reads 1.99. This is a minor release under the 0.x rule: a raised MSRV is possibly breaking per the Cargo book rules. No public API changes.

## [0.2.3] - 2026-10-07

### Changed

- Migrated view construction in `Vlad::verify`, `Builder::try_build`, `Builder::try_build_advance`, the unit tests, and the merkle example from `multi_key::Views` to `multi_key::ViewBuilder`. Requirements `multi-key` 2.0 → 2.1 and `multi-sig` 1.4 → 1.5. No public API changes.

## [0.2.2] - 2026-10-06

### Changed

- Updated dependencies: `multi-codec` 1.3 → 1.5, `multi-key` 1.2 → 2.0, `multi-sig` 1.3 → 1.4. No public API changes.

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

[0.4.0]: https://github.com/cryptidtech/multi-vlad/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/cryptidtech/multi-vlad/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/cryptidtech/multi-vlad/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/cryptidtech/multi-vlad/compare/v0.2.0...v0.2.2
[0.2.0]: https://github.com/cryptidtech/multi-vlad/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/cryptidtech/multi-vlad/releases/tag/v0.1.2
[0.1.1]: https://github.com/cryptidtech/multi-vlad/releases/tag/v0.1.1
[0.1.0]: https://github.com/cryptidtech/multi-vlad/releases/tag/v0.1.0