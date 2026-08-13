// SPDX-License-Identifier: Apache-2.0
//! Build a `Vlad` using an Ed25519 ephemeral key pair.
//!
//! This example generates a random Ed25519 multikey, creates a minimal WASM
//! first-lock script, builds a Vlad, and verifies it.

use multi_codec::Codec;
use multi_key::{Builder as MkBuilder, Multikey};
use multi_util::CodecInfo;
use multi_vlad::{Builder, Vlad};

fn main() {
    // 1. Generate a random Ed25519 signing key (the ephemeral key pair).
    let mut rng = rand::rng();
    let mk: Multikey = MkBuilder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
        .unwrap()
        .try_build()
        .unwrap();

    // 2. Create a minimal WASM first-lock script (magic + version 1).
    //    A real script would embed public keys and validation logic.
    let wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    // 3. Build the Vlad: sign the WASM with the ephemeral key (combined=true).
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

    println!("Ed25519 Vlad built and verified successfully");
    println!("  codec:       {:?}", vlad.codec());
    println!("  wasm bytes:  {}", vlad.wasm().len());
    println!("  total bytes: {}", bytes.len());
}
