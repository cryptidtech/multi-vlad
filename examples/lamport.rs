// SPDX-License-Identifier: Apache-2.0
//! Build a `Vlad` using a Lamport-SHA3-256 ephemeral key pair.
//!
//! Lamport keys are ONE-TIME: signing two different messages with the same
//! key leaks the secret key. A Vlad signs exactly one message (the WASM
//! first-lock script), so a Lamport key is a natural fit for the ephemeral
//! key pair in a Vlad.
//!
//! This example is `no_run` because the published `multi-key` crate does not
//! yet include the Lamport signing view (`sign_view` for Lamport codecs).
//! When the Lamport view ships in `multi-key`, this example will compile and
//! run unchanged.
//!
//! See the `ed25519` example for a fully runnable equivalent with Ed25519.

#![allow(unused_imports)]

use multi_codec::Codec;
use multi_key::{Builder as MkBuilder, Multikey};
use multi_util::CodecInfo;
use multi_vlad::{Builder, Vlad};

fn main() {
    // 1. Generate a random Lamport-SHA3-256 signing key (the ephemeral key pair).
    //    Lamport keys are one-time — perfect for a Vlad, which signs once.
    let mut rng = rand::rng();
    let mk: Multikey = MkBuilder::new_from_random_bytes(Codec::LamportSha3256Priv, &mut rng)
        .unwrap()
        .try_build()
        .unwrap();

    // 2. Create a minimal WASM first-lock script (magic + version 1).
    let wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    // 3. Build the Vlad: sign the WASM with the ephemeral Lamport key (combined=true).
    let vlad: Vlad = Builder::default()
        .with_signing_key(&mk)
        .with_message(&wasm)
        .try_build()
        .unwrap();

    // 4. Validate the Vlad structure: combined signature + WASM magic.
    vlad.validate().unwrap();

    // 5. Extract the WASM first-lock script.
    assert_eq!(vlad.wasm(), &wasm[..]);

    // 6. Verify the signature over the WASM against the signing key.
    vlad.verify(&mk).unwrap();

    // 7. Round-trip through bytes.
    let bytes: Vec<u8> = vlad.clone().into();
    let decoded = Vlad::try_from(&bytes[..]).unwrap();
    assert_eq!(vlad, decoded);
    decoded.verify(&mk).unwrap();

    println!("Lamport-SHA3-256 Vlad built and verified successfully");
    println!("  codec:       {:?}", vlad.codec());
    println!("  wasm bytes:  {}", vlad.wasm().len());
    println!("  total bytes: {}", bytes.len());
}
