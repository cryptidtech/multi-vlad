// SPDX-License-Identifier: Apache-2.0
//! # multi-vlad
//!
//! Verifiable Long-Lived Address (VLAD) implementation: a combined `Multisig`
//! whose message holds the WASM first-lock bytecode and whose signature is by
//! an ephemeral key pair.
//!
//! ## Overview
//!
//! This crate contains only the `Vlad` half of the former `bs-multicid`
//! workspace crate. The `Cid` half lives in the standalone `multi-cid` crate.
//! The split lets a downstream crate depend on only the type it needs:
//! `multi-vlad` depends on `multi-key` and `multi-sig` but not on `multi-hash`,
//! which was only required by `Cid`.
//!
//! ## The `Vlad(Multisig)` Construction
//!
//! A `Vlad` is a newtype over a combined `Multisig`. The `Multisig` message
//! field holds the binary WASM of a first-lock script. The signature is over
//! that script, signed by an ephemeral key pair. The `Vlad` validates that the
//! inner `Multisig` is combined (non-empty message) and that the message
//! begins with the `\0asm` WASM magic bytes.
//!
//! The goal is to avoid the anti-pattern of using public keys as identifiers.
//! Public keys are subject to compromise and rotation, so identifiers derived
//! from key material become invalid when keys change. A `Vlad` replaces the
//! public-key identifier with a random identifier (the signature bytes) plus
//! a cryptographic commitment to a validation function (the WASM script).
//!
//! ## Plog Verification Flow
//!
//! A provenance log (`Log`) uses the Vlad's WASM as its `first_lock` script.
//! The verification flow is:
//!
//! 1. Call [`Vlad::wasm`] (or [`Vlad::message`]) to extract the WASM first-lock
//!    script bytecode.
//! 2. The plog builder seeds `first_lock = Script::Bin(root_key, vlad.wasm())`.
//! 3. Call [`Vlad::verify`] to check the signature over the WASM against the
//!    signing key. This proves the VLAD was created by someone who held the
//!    ephemeral private key.
//! 4. Call [`Vlad::validate`] to confirm the inner Multisig is combined and
//!    the message is valid WASM.
//! 5. The plog `Log::verify()` iterator runs the WASM first-lock script
//!    through the wacc VM to authorize the genesis entry.
//!
//! ## Quick Start
//!
//! ```rust
//! use multi_vlad::Builder;
//! use multi_key::EncodedMultikey;
//!
//! let mk = EncodedMultikey::try_from(
//!     "fba2480260874657374206b657901012064e58adf88f85cbec6a0448a0803f9d28cf9231a7141be413f83cf6aa883cd04"
//! ).unwrap().to_inner();
//! let msg = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]; // WASM magic + version
//!
//! let vlad = Builder::default()
//!     .with_signing_key(&mk)
//!     .with_message(&msg)
//!     .try_build()
//!     .unwrap();
//!
//! // validate structure: combined sig + WASM magic
//! vlad.validate().unwrap();
//! // extract the WASM first-lock script
//! assert_eq!(vlad.wasm(), &msg[..]);
//! // verify the signature over the WASM against the signing key
//! vlad.verify(&mk).unwrap();
//! ```
//!
//! ## Features
//!
//! - **`serde`** (default): Enables serde serialization for `Vlad`.
//! - **`dag_cbor`**: Enables CBOR support for `Vlad` via `multi-cbor`.

#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
// Pedantic/nursery/cargo lints are enabled in `[lints.clippy]` in Cargo.toml.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph
)]

/// Errors produced by this library
pub mod error;
pub use error::{Error, VladError};

/// Vlad content identifier types
pub mod vlad;
pub use vlad::{Builder, EncodedVlad, Vlad};

/// Serde serialization for Vlad
#[cfg(feature = "serde")]
pub mod serde;

/// Commonly used items
///
/// ```
/// use multi_vlad::prelude::*;
/// use multi_trait::Null;
///
/// let _ = Vlad::null();
/// ```
pub mod prelude {
    pub use super::*;
    /// re-exports
    pub use multi_base::Base;
    pub use multi_codec::Codec;
}
