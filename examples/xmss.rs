// SPDX-License-Identifier: Apache-2.0
//! Build a `Vlad` using an XMSS-SHA2_10_256 post-quantum ephemeral key pair.
//!
//! A Vlad is created by signing the WASM first-lock script with an ephemeral
//! key pair. In a real deployment the same ephemeral key is later used to sign
//! the first provenance-log entry, so the key must be usable for at least two
//! signatures. XMSS is a stateful hash-based signature scheme: each private key
//! can sign a bounded number of messages (2^h for height h). XMSS-SHA2_10_256
//! (h=10) can sign up to 1024 messages per key, which is sufficient for the
//! Vlad plus its first plog entry.
//!
//! Lamport keys are one-time (one signature per key) and cannot be used for a
//! Vlad, which requires at least two signatures from the same ephemeral key.
//!
//! See the `ed25519` example for an equivalent with Ed25519.

use multi_codec::Codec;
use multi_key::{Builder as MkBuilder, Multikey};
use multi_util::CodecInfo;
use multi_vlad::{Builder, Vlad};

fn main() {
    // 1. Generate a random XMSS-SHA2_10_256 signing key (the ephemeral key pair).
    //    h=10 yields 2^10 = 1024 usable signatures — enough for the Vlad plus
    //    subsequent plog entries signed by the same ephemeral key.
    let mut rng = rand::rng();
    let mk: Multikey = MkBuilder::new_from_random_bytes(Codec::XmssSha210256Priv, &mut rng)
        .unwrap()
        .try_build()
        .unwrap();

    // 2. Create a minimal WASM first-lock script (magic + version 1).
    let wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    // 3. Build the Vlad: sign the WASM with the ephemeral XMSS key (combined=true).
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

    println!("XMSS-SHA2_10_256 Vlad built and verified successfully");
    println!("  codec:       {:?}", vlad.codec());
    println!("  wasm bytes:  {}", vlad.wasm().len());
    println!("  total bytes: {}", bytes.len());
}
