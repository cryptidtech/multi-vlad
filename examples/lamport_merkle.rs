// SPDX-License-Identifier: Apache-2.0
//! Build a `Vlad` using a merkle-tree Lamport post-quantum ephemeral key pair.
//!
//! A Vlad is created by signing the WASM first-lock script with an ephemeral
//! key pair. In a real deployment the same ephemeral key is later used to sign
//! the first provenance-log entry, so the key must be usable for at least two
//! signatures. Merkle-tree Lamport (`lamport-merkle-blake3-256`) is a stateful
//! hash-based scheme: a tree of depth `d` holds `2^d` one-time Lamport leaves.
//! At depth 1 that is exactly two signatures — one for the Vlad and one for
//! the first provenance-log entry.
//!
//! Merkle keys are stateful: [`Builder::try_build_advance`] returns both the
//! Vlad and the advanced key state. The caller MUST persist the advanced key
//! so the consumed leaf is never reused.
//!
//! See the `xmss` example for a larger-capacity stateful alternative and the
//! `ed25519` example for an equivalent with Ed25519.

use multi_codec::Codec;
use multi_key::{Builder as MkBuilder, Multikey};
use multi_util::CodecInfo as _;
use multi_vlad::{Builder, Vlad};

fn main() {
    // 1. Generate a random depth-1 merkle-Lamport signing key (the ephemeral
    //    key pair). Depth 1 yields 2^1 = 2 one-time signatures — exactly what
    //    a Vlad plus its first provenance-log entry needs.
    let mut rng = rand::rng();
    let mk: Multikey =
        MkBuilder::new_from_random_bytes_with_depth(Codec::LamportMerkleBlake3256Priv, 1, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

    // 2. Create a minimal WASM first-lock script (magic + version 1).
    //    A real script would embed public keys and validation logic.
    let wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    // 3. Build the Vlad: sign the WASM with the ephemeral merkle key
    //    (combined=true) and capture the advanced key state.
    let (vlad, advanced): (Vlad, Multikey) = Builder::default()
        .with_signing_key(&mk)
        .with_message(&wasm)
        .try_build_advance()
        .unwrap();

    // 4. Validate the Vlad structure: combined signature + WASM magic.
    vlad.validate().unwrap();

    // 5. Extract the WASM first-lock script.
    assert_eq!(vlad.wasm(), &wasm[..]);

    // 6. Verify the signature over the WASM. Both the original key and the
    //    advanced key work (the merkle root does not change on advance).
    vlad.verify(&mk).unwrap();
    vlad.verify(&advanced).unwrap();

    // 7. Round-trip through bytes and re-verify with the advanced key.
    let bytes: Vec<u8> = vlad.clone().into();
    let decoded = Vlad::try_from(&bytes[..]).unwrap();
    assert_eq!(vlad, decoded);
    decoded.verify(&advanced).unwrap();

    // 8. In a real deployment the `advanced` key MUST be persisted now: leaf 0
    //    is consumed and the next signature (the first plog entry) uses leaf 1.
    let mv = multi_key::ViewBuilder::new(&advanced)
        .merkle_state()
        .build()
        .unwrap();
    assert_eq!(mv.next_index().unwrap(), 1);
    assert_eq!(mv.remaining_signatures().unwrap(), 1);

    println!("merkle-Lamport (blake3-256, depth 1) Vlad built and verified successfully");
    println!("  codec:        {:?}", vlad.codec());
    println!("  wasm bytes:   {}", vlad.wasm().len());
    println!("  total bytes:  {}", bytes.len());
    println!("  leaves left:  {}", mv.remaining_signatures().unwrap());
}
