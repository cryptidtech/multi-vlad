// SPDX-License-Identifier: Apache-2.0
use crate::{error::VladError, Error};
use core::fmt;
use multi_base::Base;
use multi_codec::Codec;
use multi_key::{Multikey, Views};
use multi_sig::Multisig;
use multi_trait::{EncodeInto, Null, TryDecodeFrom};
use multi_util::{BaseEncoded, CodecInfo, DetectedEncoder, EncodingInfo};

/// the Vlad multicodec sigil
pub const SIGIL: Codec = Codec::Vlad;

/// WASM binary magic bytes: \0asm
const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];

/// a multibase encoded Vlad that can decode from any number of encoding but always encodes to
/// Vlad's preferred `Base32Lower` multibase encoding (i.e. liberal in what we except, strict in what
/// we generate)
pub type EncodedVlad = BaseEncoded<Vlad, DetectedEncoder>;

/// A verifiable long-lived address (VLAD) is a newtype over a combined Multisig whose message
/// contains the binary WASM of a first-lock script and whose signature is over that script signed
/// by an ephemeral key pair.
///
/// The goal is to avoid the anti-pattern of using public keys as identifiers. Public keys are
/// chosen because they are random and unique enough to be useful identifiers and are also a
/// cryptographic commitment to a validation function--the public key signature validation
/// function. Using public keys as an identifer is an anti-pattern because using key material means
/// that the identifiers are subject to compromise and must be rotated often to maintain security
/// so their "shelf-life" is limited. Rotating and/or abandoning keys due to compromise causes the
/// identifier to become invalid. Any system that stores these identifiers then possesses broken
/// links to the value the identifier is associated with.
///
/// The solution is to realize that we only need a random identifier and a cryptographic commitment
/// to a validation function to replace keys as identifiers. VLADs meet those requirements.
#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Vlad(pub(crate) Multisig);

impl Vlad {
    /// Construct a `Vlad` from a combined `Multisig`.
    ///
    /// The `Multisig` message must hold the WASM first-lock script bytecode and
    /// the signature must be over that bytecode. Call [`Vlad::validate`] after
    /// construction to enforce the combined-signature and WASM-magic invariants.
    ///
    /// This constructor is intended for callers that build a `Multisig`
    /// directly (e.g. via a signing view) rather than through the
    /// [`Builder`]. The [`Builder`] is the preferred path for most callers.
    #[must_use]
    pub const fn new(multisig: Multisig) -> Self {
        Self(multisig)
    }

    /// Validate that the inner Multisig is a combined signature with a valid
    /// WASM binary message.
    ///
    /// Null Vlads are exempt from validation (sentinel value).
    ///
    /// # Errors
    ///
    /// Returns [`VladError::NotCombined`] if the inner Multisig has an empty
    /// message (detached signature). Returns [`VladError::InvalidWasm`] if the
    /// message does not begin with the `\0asm` WASM magic bytes.
    pub fn validate(&self) -> Result<(), Error> {
        // null Multisig is a valid sentinel value
        if self.0.is_null() {
            return Ok(());
        }
        if self.0.message.is_empty() {
            return Err(VladError::NotCombined.into());
        }
        if self.0.message.len() < 4 || self.0.message[..4] != WASM_MAGIC {
            return Err(VladError::InvalidWasm.into());
        }
        Ok(())
    }

    /// Verify a Vlad whose inner Multisig is a combined signature over the
    /// WASM first-lock script.
    ///
    /// This checks that the signature in the inner Multisig is a valid
    /// signature over the WASM bytecode (the `message` field) made by the
    /// given signing key. This proves the VLAD was created by someone who
    /// held the private half of `mk`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not match the signature, or if the
    /// underlying `multi-key`/`multi-sig` verification fails.
    pub fn verify(&self, mk: &Multikey) -> Result<(), Error> {
        let vv = mk.verify_view()?;
        vv.verify(&self.0, Some(&self.0.message))?;
        Ok(())
    }

    /// Get a reference to the inner Multisig.
    ///
    /// The verifier needs this to access the raw signature bytes (stored in
    /// `multisig().attributes` under `AttrId::SigData`) and the signing
    /// codec.
    #[must_use]
    pub const fn multisig(&self) -> &Multisig {
        &self.0
    }

    /// Get the WASM first-lock script bytecode.
    ///
    /// This is the WASM that the plog uses as its `first_lock` script. The
    /// plog `Log` builder calls `vlad.message()` to seed
    /// `first_lock = Script::Bin(root_key, vlad.message())`.
    ///
    /// The returned slice is the `message` field of the inner combined
    /// Multisig. It always begins with the `\0asm` WASM magic bytes for a
    /// non-null Vlad.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.0.message
    }

    /// Get the WASM first-lock script bytecode.
    ///
    /// This is an alias for [`Vlad::message`] named for the plog use case.
    /// The plog verification flow calls `vlad.wasm()` to extract the WASM
    /// first-lock script and then runs it through the wacc VM to authorize
    /// the genesis entry.
    #[must_use]
    pub fn wasm(&self) -> &[u8] {
        self.message()
    }
}

impl CodecInfo for Vlad {
    /// Return that we are a Vlad object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the codec for this object
    fn codec(&self) -> Codec {
        Self::preferred_codec()
    }
}

impl EncodingInfo for Vlad {
    fn preferred_encoding() -> Base {
        Base::Base32Lower
    }

    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl From<Vlad> for Vec<u8> {
    fn from(vlad: Vlad) -> Self {
        let mut v = Self::default();
        // add the sigil
        let sigil_bytes: Self = SIGIL.into();
        v.extend_from_slice(&sigil_bytes);
        // add the multisig
        let ms_bytes: Self = vlad.0.into();
        v.extend_from_slice(&ms_bytes);
        v
    }
}

impl EncodeInto for Vlad {
    fn encode_into(&self) -> Vec<u8> {
        self.clone().into()
    }
}

impl<'a> TryFrom<&'a [u8]> for Vlad {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (vlad, _) = Self::try_decode_from(s)?;
        Ok(vlad)
    }
}

impl<'a> TryDecodeFrom<'a> for Vlad {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(VladError::MissingSigil.into());
        }
        // decode the multisig
        let (ms, ptr) = Multisig::try_decode_from(ptr)?;
        let vlad = Self(ms);
        // validate combined + WASM message
        vlad.validate()?;
        Ok((vlad, ptr))
    }
}

impl Null for Vlad {
    fn null() -> Self {
        Self(Multisig::null())
    }

    fn is_null(&self) -> bool {
        *self == Self::null()
    }
}

impl fmt::Debug for Vlad {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} - {:?}", SIGIL, self.0)
    }
}

/// Builder for constructing Vlad instances from a signing key and message bytes
#[derive(Clone, Debug, Default)]
pub struct Builder {
    mk: Option<Multikey>,
    message: Option<Vec<u8>>,
    base_encoding: Option<Base>,
}

impl Builder {
    /// set the signing key (ephemeral key)
    #[must_use]
    pub fn with_signing_key(mut self, mk: &Multikey) -> Self {
        self.mk = Some(mk.clone());
        self
    }

    /// set the message bytes (serialized first-lock script)
    #[must_use]
    pub fn with_message(mut self, msg: &[u8]) -> Self {
        self.message = Some(msg.to_vec());
        self
    }

    /// set the base encoding codec
    #[must_use]
    pub const fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// build a base encoded vlad
    pub fn try_build_encoded(&self) -> Result<EncodedVlad, Error> {
        Ok(EncodedVlad::new(
            self.base_encoding.unwrap_or_else(Vlad::preferred_encoding),
            self.try_build()?,
        ))
    }

    /// build the vlad
    pub fn try_build(&self) -> Result<Vlad, Error> {
        let mk = self.mk.as_ref().ok_or(VladError::MissingSigningKey)?;
        let msg = self.message.as_ref().ok_or(VladError::MissingMessage)?;
        // validate message is WASM binary before signing
        if msg.len() < 4 || msg[..4] != WASM_MAGIC {
            return Err(VladError::InvalidWasm.into());
        }
        let sv = mk.sign_view()?;
        // combined=true: message is stored inside the Multisig
        let ms = sv.sign(msg, true, None)?;
        Ok(Vlad(ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use multi_key::EncodedMultikey;
    use multi_util::{base_name, BaseIter};

    /// Helper: returns a deterministic Ed25519 secret key for testing
    fn test_signing_key() -> Multikey {
        let s = "fba2480260874657374206b657901012064e58adf88f85cbec6a0448a0803f9d28cf9231a7141be413f83cf6aa883cd04";
        EncodedMultikey::try_from(s).unwrap().to_inner()
    }

    /// Helper: returns a minimal valid WASM module (magic + version 1)
    fn test_wasm_message() -> Vec<u8> {
        vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
    }

    #[test]
    fn test_default() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad = Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build()
            .unwrap();

        assert_eq!(Codec::Vlad, vlad.codec());
    }

    #[test]
    fn test_binary_roundtrip() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad = Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build()
            .unwrap();

        let v: Vec<u8> = vlad.clone().into();
        assert_eq!(vlad, Vlad::try_from(v.as_ref()).unwrap());
    }

    #[test]
    fn test_encoded_roundtrip() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad = Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build_encoded()
            .unwrap();

        let s = vlad.to_string();
        assert_eq!(vlad, EncodedVlad::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_encodings_roundtrip() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        // start at Identity so we skip it
        let itr: BaseIter = Base::Identity.into();

        for encoding in itr {
            let vlad = Builder::default()
                .with_signing_key(&mk)
                .with_message(&msg)
                .with_base_encoding(encoding)
                .try_build_encoded()
                .unwrap();

            let s = vlad.to_string();
            println!("{}: ({}) {}", base_name(encoding), s.len(), s);
            assert_eq!(vlad, EncodedVlad::try_from(s.as_str()).unwrap());
        }
    }

    #[test]
    fn test_signed_vlad() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad = Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .with_base_encoding(Base::Base32Z)
            .try_build_encoded()
            .unwrap();

        // make sure the signature checks out
        vlad.verify(&mk).unwrap();
        let s = vlad.to_string();
        let de = EncodedVlad::try_from(s.as_str()).unwrap();
        assert_eq!(vlad, de);
        assert_eq!(Base::Base32Z, de.encoding());
        let vlad = vlad.to_inner();
        let v: Vec<u8> = vlad.clone().into();
        assert_eq!(vlad, Vlad::try_from(v.as_ref()).unwrap());
    }

    #[test]
    fn test_verify_wrong_key() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad = Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build()
            .unwrap();

        // create a different key
        let wrong_key_str = "fba2480260874657374206b657902012064e58adf88f85cbec6a0448a0803f9d28cf9231a7141be413f83cf6aa883cd04";
        let wrong_key = EncodedMultikey::try_from(wrong_key_str);
        // if the wrong key string is valid, verify should fail
        if let Ok(wk) = wrong_key {
            assert!(vlad.verify(&wk).is_err());
        }
    }

    #[test]
    fn test_message_accessor() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad = Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build()
            .unwrap();

        assert_eq!(vlad.message(), msg.as_slice());
    }

    #[test]
    fn test_multisig_accessor() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad = Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build()
            .unwrap();

        // inner multisig should be combined (non-empty message)
        assert!(!vlad.multisig().message.is_empty());
    }

    #[test]
    fn test_null() {
        let v1 = Vlad::null();
        assert!(v1.is_null());
        // Multisig::null() == Multisig::default(), so Vlad::null() == Vlad::default()
        let v2 = Vlad::default();
        assert_eq!(v1, v2);
        assert!(v2.is_null());
    }

    #[test]
    fn test_equality() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad1 = Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build()
            .unwrap();

        // roundtrip through bytes
        let v: Vec<u8> = vlad1.clone().into();
        let vlad2 = Vlad::try_from(v.as_ref()).unwrap();

        assert_eq!(vlad1, vlad2);
    }

    #[test]
    fn test_missing_signing_key() {
        let msg = test_wasm_message();
        let result = Builder::default().with_message(&msg).try_build();
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_message() {
        let mk = test_signing_key();
        let result = Builder::default().with_signing_key(&mk).try_build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_rejects_non_wasm_message() {
        let mk = test_signing_key();
        let bad_msg = b"not a wasm module";
        let result = Builder::default()
            .with_signing_key(&mk)
            .with_message(bad_msg)
            .try_build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), "Vlad");
    }

    #[test]
    fn test_builder_rejects_short_message() {
        let mk = test_signing_key();
        let short_msg = &[0x00, 0x61, 0x73]; // only 3 bytes, needs 4 for magic
        let result = Builder::default()
            .with_signing_key(&mk)
            .with_message(short_msg)
            .try_build();
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_rejects_detached_multisig() {
        let mk = test_signing_key();
        let msg = test_wasm_message();
        let sv = mk.sign_view().unwrap();
        // sign with combined=false to create a detached signature
        let ms = sv.sign(&msg, false, None).unwrap();
        // manually construct a Vlad with a detached Multisig and try to serialize/decode
        let mut v = Vec::default();
        let sigil_bytes: Vec<u8> = SIGIL.into();
        v.extend_from_slice(&sigil_bytes);
        let ms_bytes: Vec<u8> = ms.into();
        v.extend_from_slice(&ms_bytes);
        let result = Vlad::try_from(v.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_rejects_non_wasm_message() {
        let mk = test_signing_key();
        let bad_msg = b"not a wasm module at all!";
        let sv = mk.sign_view().unwrap();
        // sign with combined=true but non-WASM message
        let ms = sv.sign(bad_msg.as_slice(), true, None).unwrap();
        let mut v = Vec::default();
        let sigil_bytes: Vec<u8> = SIGIL.into();
        v.extend_from_slice(&sigil_bytes);
        let ms_bytes: Vec<u8> = ms.into();
        v.extend_from_slice(&ms_bytes);
        let result = Vlad::try_from(v.as_slice());
        assert!(result.is_err());
    }

    /// Demonstrate the plog verification flow usage pattern:
    /// extract the WASM first-lock script from the Vlad, verify it is valid
    /// WASM, and verify the Vlad signature against the signing key.
    #[test]
    fn test_plog_verification_flow() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad = Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build()
            .unwrap();

        // 1. validate the Vlad structure (combined sig + WASM message)
        vlad.validate().unwrap();

        // 2. extract the WASM first-lock script
        let wasm = vlad.wasm();
        assert_eq!(wasm, msg.as_slice());
        assert_eq!(&wasm[..4], &WASM_MAGIC);

        // 3. the plog would build first_lock = Script::Bin(root_key, vlad.wasm())
        //    (the Script construction happens in provenance-log, not here)

        // 4. verify the Vlad signature over the WASM against the signing key
        vlad.verify(&mk).unwrap();

        // 5. round-trip through bytes and re-verify
        let bytes: Vec<u8> = vlad.clone().into();
        let decoded = Vlad::try_from(bytes.as_ref()).unwrap();
        assert_eq!(vlad, decoded);
        decoded.validate().unwrap();
        decoded.verify(&mk).unwrap();

        // 6. the message() accessor returns the same bytes as wasm()
        assert_eq!(vlad.message(), vlad.wasm());
    }
}
