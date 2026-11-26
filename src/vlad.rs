// SPDX-License-Identifier: Apache-2.0
use crate::{error::VladError, Error};
use core::fmt;
use multi_base::Base;
use multi_codec::Codec;
use multi_key::{Multikey, ViewBuilder};
use multi_sig::Multisig;
use multi_trait::{EncodeInto, EncodeIntoBuffer, Null, TryDecodeFrom};
use multi_util::{BaseEncoded, CodecInfo, DetectedEncoder, EncodingInfo};

/// the Vlad multicodec sigil
pub const SIGIL: Codec = Codec::Vlad;

/// WASM binary magic bytes: \0asm
const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];

/// WASM version byte of a binary WASM component, following the \0asm magic.
/// The version byte identifies the component script form, the only script
/// form of a first-lock message.
const COMPONENT_VERSION_BYTE: u8 = 0x0d;

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
    /// construction to enforce the combined-signature and WASM
    /// component-form invariants.
    ///
    /// This constructor is intended for callers that build a `Multisig`
    /// directly (e.g. via a signing view) rather than through the
    /// [`Builder`]. The [`Builder`] is the preferred path for most callers.
    #[must_use]
    pub const fn new(multisig: Multisig) -> Self {
        Self(multisig)
    }

    /// Validate that the inner Multisig is a combined signature with a valid
    /// WASM component-form message.
    ///
    /// Null Vlads are exempt from validation (sentinel value).
    ///
    /// # Errors
    ///
    /// Returns [`VladError::NotCombined`] if the inner Multisig has an empty
    /// message (detached signature). Returns [`VladError::InvalidWasm`] if the
    /// message does not begin with the `\0asm` WASM magic bytes. Returns
    /// [`VladError::ScriptForm`] if the message is not the component form:
    /// the version byte that follows the magic is not `0x0d`.
    pub fn validate(&self) -> Result<(), Error> {
        // null Multisig is a valid sentinel value
        if self.0.is_null() {
            return Ok(());
        }
        if self.0.message.is_empty() {
            return Err(VladError::NotCombined.into());
        }
        // validate the message is the WASM component form
        check_component_form(&self.0.message)?;
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
        let vv = ViewBuilder::new(mk).verify().build()?;
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
    /// Multisig. It is the `\0asm` magic followed by the `0x0d` component
    /// version byte for a non-null Vlad.
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

impl EncodeIntoBuffer for Vlad {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.clone().encode_into());
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
    ///
    /// The message must carry the WASM component form: the `\0asm` magic
    /// followed by the `0x0d` component version byte. Any other WASM form
    /// rejects with [`VladError::ScriptForm`] before the message is signed.
    pub fn try_build(&self) -> Result<Vlad, Error> {
        let mk = self.mk.as_ref().ok_or(VladError::MissingSigningKey)?;
        let msg = self.message.as_ref().ok_or(VladError::MissingMessage)?;
        // validate the message is the WASM component form before signing
        check_component_form(msg)?;
        let sv = ViewBuilder::new(mk).sign().build()?;
        // combined=true: message is stored inside the Multisig
        let ms = sv.sign(msg, true, None)?;
        Ok(Vlad(ms))
    }

    /// build the vlad with a stateful signing key, returning the vlad AND the
    /// advanced key state
    ///
    /// Stateful signature schemes (merkle-tree Lamport, XMSS) consume a
    /// one-time slot per signature. The caller MUST persist the returned
    /// advanced key so the consumed slot is never reused. The advanced key
    /// verifies the vlad just like the original key (the tree root does not
    /// change when the state advances).
    ///
    /// Stateless keys return an error: use [`try_build`](Self::try_build).
    pub fn try_build_advance(&self) -> Result<(Vlad, Multikey), Error> {
        let mk = self.mk.as_ref().ok_or(VladError::MissingSigningKey)?;
        let msg = self.message.as_ref().ok_or(VladError::MissingMessage)?;
        // validate the message is the WASM component form before signing
        check_component_form(msg)?;
        let sv = ViewBuilder::new(mk).sign().build()?;
        // combined=true: message is stored inside the Multisig
        let (ms, advanced) = sv.sign_advance(msg, true, None)?;
        Ok((Vlad(ms), advanced))
    }

    /// build a base encoded vlad with a stateful signing key, returning the
    /// encoded vlad AND the advanced key state
    ///
    /// See [`try_build_advance`](Self::try_build_advance).
    pub fn try_build_advance_encoded(&self) -> Result<(EncodedVlad, Multikey), Error> {
        let (vlad, advanced) = self.try_build_advance()?;
        Ok((
            EncodedVlad::new(
                self.base_encoding.unwrap_or_else(Vlad::preferred_encoding),
                vlad,
            ),
            advanced,
        ))
    }

    /// build the genesis Vlad of the log-foot genesis
    ///
    /// A log-foot genesis authorizes the log's first entry under the VLAD
    /// first lock, and that first lock is the root key path's lock script of
    /// the genesis install. The root lock script mandate requires the root
    /// key path to carry exactly one multiproof verifier script, which is a
    /// WASM component, so the genesis Vlad's message carries the component
    /// form. The component-form rule of [`try_build`](Self::try_build)
    /// rejects any other WASM form with [`VladError::ScriptForm`], and the
    /// genesis duty checks the message before the signing state.
    ///
    /// The other genesis class is the fork-child genesis: the child log
    /// forks under a new Vlad, and the parent governing script at the fork
    /// point stays the child genesis's first lock, so the fork-child Vlad's
    /// own message carries no root-pattern duty. The genesis classes keep
    /// the key-publication evidence duty and install the multiproof-era
    /// locks, including the root pattern, in their genesis entries' lock
    /// lists.
    ///
    /// # Errors
    ///
    /// Reports [`VladError::ScriptForm`] for a message that is not the WASM
    /// component form, and the errors of [`try_build`](Self::try_build).
    pub fn try_build_genesis(&self) -> Result<Vlad, Error> {
        self.try_build_genesis_inner(Self::try_build)
    }

    /// build the genesis Vlad of the log-foot genesis with a stateful
    /// signing key, returning the genesis Vlad AND the advanced key state
    ///
    /// The genesis rule of [`try_build_genesis`](Self::try_build_genesis)
    /// applies, and the caller must persist the returned advanced key so the
    /// consumed one-time slot is never reused.
    ///
    /// # Errors
    ///
    /// Reports [`VladError::ScriptForm`] for a message that is not the WASM
    /// component form, and the errors of
    /// [`try_build_advance`](Self::try_build_advance).
    pub fn try_build_genesis_advance(&self) -> Result<(Vlad, Multikey), Error> {
        self.try_build_genesis_inner(Self::try_build_advance)
    }

    /// build a base encoded genesis Vlad, with the stateless signing path
    ///
    /// The genesis rule of [`try_build_genesis`](Self::try_build_genesis)
    /// applies.
    ///
    /// # Errors
    ///
    /// Reports [`VladError::ScriptForm`] for a message that is not the WASM
    /// component form, and the errors of
    /// [`try_build_encoded`](Self::try_build_encoded).
    pub fn try_build_genesis_encoded(&self) -> Result<EncodedVlad, Error> {
        self.try_build_genesis_inner(Self::try_build_encoded)
    }

    /// build a base encoded genesis Vlad with a stateful signing key,
    /// returning the encoded genesis Vlad AND the advanced key state
    ///
    /// See [`try_build_genesis_advance`](Self::try_build_genesis_advance).
    ///
    /// # Errors
    ///
    /// Reports [`VladError::ScriptForm`] for a message that is not the WASM
    /// component form, and the errors of
    /// [`try_build_advance_encoded`](Self::try_build_advance_encoded).
    pub fn try_build_genesis_advance_encoded(&self) -> Result<(EncodedVlad, Multikey), Error> {
        self.try_build_genesis_inner(Self::try_build_advance_encoded)
    }

    /// builds through `path` after the genesis first-lock duty passes
    ///
    /// The genesis duty is the root-pattern rule of the log-foot genesis:
    /// the first lock is the root key path's lock script, so `self.message`
    /// must carry the multiproof verifier component form. The duty checks
    /// the message before it signs, and a missing message reports the same
    /// [`VladError::MissingMessage`] the build path reports.
    fn try_build_genesis_inner<T>(
        &self,
        path: impl FnOnce(&Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let msg = self.message.as_ref().ok_or(VladError::MissingMessage)?;
        check_component_form(msg)?;
        path(self)
    }
}

/// the WASM component-form check the builders share: a first-lock message is
/// the \0asm magic followed by the `0x0d` component version byte
///
/// A message that is shorter than the magic, or that misses the magic,
/// reports [`VladError::InvalidWasm`]. A message that passes the magic check
/// but stops before the version byte, or that carries any other value there,
/// rejects as not the component form: [`VladError::ScriptForm`].
fn check_component_form(msg: &[u8]) -> Result<(), VladError> {
    if msg.len() < 4 || msg[..4] != WASM_MAGIC {
        return Err(VladError::InvalidWasm);
    }
    if msg.len() < 5 || msg[4] != COMPONENT_VERSION_BYTE {
        return Err(VladError::ScriptForm);
    }
    Ok(())
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

    /// Helper: a minimal WASM component artifact (magic + component version)
    fn test_component_message() -> Vec<u8> {
        vec![0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00]
    }

    /// Helper: a WASM core module (magic + version 1), the rejected script
    /// form
    fn test_module_form_message() -> Vec<u8> {
        vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
    }

    /// Helper: a WASM binary whose version byte is not the component version
    fn test_unknown_form_message() -> Vec<u8> {
        vec![0x00, 0x61, 0x73, 0x6d, 0x02, 0x00, 0x00, 0x00]
    }

    /// Helper: a WASM binary that stops after the \0asm magic, with no
    /// version byte
    fn test_magic_only_message() -> Vec<u8> {
        WASM_MAGIC.to_vec()
    }

    #[test]
    fn test_default() {
        let mk = test_signing_key();
        let msg = test_component_message();

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
        let msg = test_component_message();

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
        let msg = test_component_message();

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
        let msg = test_component_message();

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
        let msg = test_component_message();

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
        let msg = test_component_message();

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
        let msg = test_component_message();

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
        let msg = test_component_message();

        let vlad = Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build()
            .unwrap();

        // inner multisig should be combined (non-empty message)
        assert_ne!(vlad.multisig().message, Vec::<u8>::new());
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
        let msg = test_component_message();

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
        let msg = test_component_message();
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
    fn test_builder_rejects_the_module_form() {
        let mk = test_signing_key();

        // the stateless build path rejects the module form: the message is
        // not the component form
        let result = Builder::default()
            .with_signing_key(&mk)
            .with_message(&test_module_form_message())
            .try_build();
        assert!(matches!(result, Err(Error::Vlad(VladError::ScriptForm))));

        // the stateful build path rejects the module form too
        let result = Builder::default()
            .with_signing_key(&mk)
            .with_message(&test_module_form_message())
            .try_build_advance();
        assert!(matches!(result, Err(Error::Vlad(VladError::ScriptForm))));
    }

    #[test]
    fn test_builder_rejects_a_magic_only_message() {
        let mk = test_signing_key();

        // the magic check passes but no version byte follows it
        let result = Builder::default()
            .with_signing_key(&mk)
            .with_message(&test_magic_only_message())
            .try_build();
        assert!(matches!(result, Err(Error::Vlad(VladError::ScriptForm))));
    }

    #[test]
    fn test_builder_rejects_an_unknown_form() {
        let mk = test_signing_key();

        // an unknown version byte rejects as not the component form
        let result = Builder::default()
            .with_signing_key(&mk)
            .with_message(&test_unknown_form_message())
            .try_build();
        assert!(matches!(result, Err(Error::Vlad(VladError::ScriptForm))));
    }

    #[test]
    fn test_decode_rejects_detached_multisig() {
        let mk = test_signing_key();
        let msg = test_component_message();
        let sv = ViewBuilder::new(&mk).sign().build().unwrap();
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
        let sv = ViewBuilder::new(&mk).sign().build().unwrap();
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

    #[test]
    fn test_decode_rejects_the_module_form() {
        let mk = test_signing_key();
        let sv = ViewBuilder::new(&mk).sign().build().unwrap();
        // sign with combined=true but a module-form message
        let ms = sv.sign(&test_module_form_message(), true, None).unwrap();
        let mut v = Vec::default();
        let sigil_bytes: Vec<u8> = SIGIL.into();
        v.extend_from_slice(&sigil_bytes);
        let ms_bytes: Vec<u8> = ms.into();
        v.extend_from_slice(&ms_bytes);
        let result = Vlad::try_from(v.as_slice());
        assert!(matches!(result, Err(Error::Vlad(VladError::ScriptForm))));
    }

    /// Demonstrate the plog verification flow usage pattern:
    /// extract the WASM first-lock script from the Vlad, verify it is valid
    /// WASM, and verify the Vlad signature against the signing key.
    #[test]
    fn test_plog_verification_flow() {
        let mk = test_signing_key();
        let msg = test_component_message();

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

    #[test]
    fn test_merkle_vlad_sign_and_verify() {
        let mut rng = rand::rng();
        let mk = multi_key::Builder::new_from_random_bytes_with_depth(
            Codec::LamportMerkleBlake3256Priv,
            1,
            &mut rng,
        )
        .unwrap()
        .try_build()
        .unwrap();
        let msg = test_component_message();

        let (vlad, advanced) = Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build_advance()
            .unwrap();

        // structure checks
        vlad.validate().unwrap();
        assert_eq!(vlad.wasm(), msg.as_slice());

        // the signature carries the depth attribute
        let ms = vlad.multisig();
        assert_eq!(ms.depth(), Some(1));

        // both the original and the advanced key verify (same tree root)
        vlad.verify(&mk).unwrap();
        vlad.verify(&advanced).unwrap();

        // round-trip through bytes and re-verify with the advanced key
        let bytes: Vec<u8> = vlad.clone().into();
        let decoded = Vlad::try_from(bytes.as_ref()).unwrap();
        assert_eq!(vlad, decoded);
        decoded.validate().unwrap();
        decoded.verify(&advanced).unwrap();

        // the advanced key consumed leaf 0 of the 2-leaf tree
        let mv = ViewBuilder::new(&advanced).merkle_state().build().unwrap();
        assert_eq!(mv.depth().unwrap(), 1);
        assert_eq!(mv.capacity().unwrap(), 2);
        assert_eq!(mv.next_index().unwrap(), 1);
        assert_eq!(mv.remaining_signatures().unwrap(), 1);
    }

    #[test]
    fn test_merkle_vlad_exhausts_after_two_signs() {
        let mut rng = rand::rng();
        let mk = multi_key::Builder::new_from_random_bytes_with_depth(
            Codec::LamportMerkleBlake3256Priv,
            1,
            &mut rng,
        )
        .unwrap()
        .try_build()
        .unwrap();
        let msg = test_component_message();

        // leaf 0 signs the vlad
        let (_vlad, advanced) = Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build_advance()
            .unwrap();

        // leaf 1 signs a second message via sign_advance on the advanced key
        let sv = ViewBuilder::new(&advanced).sign().build().unwrap();
        let (_ms2, exhausted) = sv.sign_advance(b"second message", false, None).unwrap();

        // the tree is empty; a third signature fails
        let sv3 = ViewBuilder::new(&exhausted).sign().build().unwrap();
        assert!(sv3.sign_advance(b"third message", false, None).is_err());

        // the stateless sign path never worked for merkle keys
        assert!(Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build()
            .is_err());
    }

    #[test]
    fn test_merkle_vlad_rejects_wrong_depth_attr() {
        let mut rng = rand::rng();
        let mut mk = multi_key::Builder::new_from_random_bytes_with_depth(
            Codec::LamportMerkleBlake3256Priv,
            1,
            &mut rng,
        )
        .unwrap()
        .try_build()
        .unwrap();

        // tamper the depth attribute: wire says 1, attr now says 2
        mk.attributes
            .insert(multi_key::AttrId::Depth, zeroize::Zeroizing::new(vec![2]));

        assert!(Builder::default()
            .with_signing_key(&mk)
            .with_message(&test_component_message())
            .try_build_advance()
            .is_err());
    }

    #[test]
    fn test_try_build_genesis_accepts_the_verifier_component_form() {
        let mk = test_signing_key();

        let vlad = Builder::default()
            .with_signing_key(&mk)
            .with_message(&test_component_message())
            .try_build_genesis()
            .unwrap();

        // the genesis install carries the multiproof verifier form, and the
        // genesis signature verifies the first lock against the key
        assert_eq!(vlad.message()[4], COMPONENT_VERSION_BYTE);
        vlad.validate().unwrap();
        vlad.verify(&mk).unwrap();
    }

    #[test]
    fn test_try_build_genesis_rejects_the_module_form() {
        let mk = test_signing_key();

        let result = Builder::default()
            .with_signing_key(&mk)
            .with_message(&test_module_form_message())
            .try_build_genesis();

        assert!(matches!(result, Err(Error::Vlad(VladError::ScriptForm))));
    }

    #[test]
    fn test_try_build_genesis_rejects_an_unknown_form() {
        let mk = test_signing_key();

        let result = Builder::default()
            .with_signing_key(&mk)
            .with_message(&test_unknown_form_message())
            .try_build_genesis();

        assert!(matches!(result, Err(Error::Vlad(VladError::ScriptForm))));
    }

    #[test]
    fn test_try_build_genesis_rejects_a_non_wasm_message() {
        let mk = test_signing_key();

        let result = Builder::default()
            .with_signing_key(&mk)
            .with_message(b"not a wasm module")
            .try_build_genesis();

        assert!(matches!(result, Err(Error::Vlad(VladError::InvalidWasm))));
    }

    #[test]
    fn test_try_build_genesis_reports_missing_inputs() {
        let mk = test_signing_key();

        // a missing message: the genesis duty reports the same missing
        // message error the build path reports
        let result = Builder::default().with_signing_key(&mk).try_build_genesis();
        assert!(matches!(
            result,
            Err(Error::Vlad(VladError::MissingMessage))
        ));

        // a missing signing key: the build path reports it
        let result = Builder::default()
            .with_message(&test_component_message())
            .try_build_genesis();
        assert!(matches!(
            result,
            Err(Error::Vlad(VladError::MissingSigningKey))
        ));
    }

    #[test]
    fn test_try_build_genesis_encoded_roundtrip() {
        let mk = test_signing_key();

        let vlad = Builder::default()
            .with_signing_key(&mk)
            .with_message(&test_component_message())
            .with_base_encoding(Base::Base32Lower)
            .try_build_genesis_encoded()
            .unwrap();

        let s = vlad.to_string();
        let de = EncodedVlad::try_from(s.as_str()).unwrap();
        assert_eq!(de.to_inner().message()[4], COMPONENT_VERSION_BYTE);
    }

    #[test]
    fn test_genesis_advance_for_a_one_time_key() {
        let mut rng = rand::rng();
        let mk = multi_key::Builder::new_from_random_bytes_with_depth(
            Codec::LamportMerkleBlake3256Priv,
            1,
            &mut rng,
        )
        .unwrap()
        .try_build()
        .unwrap();

        let (vlad, advanced) = Builder::default()
            .with_signing_key(&mk)
            .with_message(&test_component_message())
            .try_build_genesis_advance()
            .unwrap();

        // the genesis install carries the multiproof verifier form
        assert_eq!(vlad.message()[4], COMPONENT_VERSION_BYTE);

        // the advanced key verifies the genesis vlad (same tree root)
        vlad.verify(&advanced).unwrap();

        // the genesis signature consumed the one-time slot at leaf 0
        let mv = ViewBuilder::new(&advanced).merkle_state().build().unwrap();
        assert_eq!(mv.next_index().unwrap(), 1);
    }

    #[test]
    fn test_genesis_advance_encoded_roundtrip() {
        let mut rng = rand::rng();
        let mk = multi_key::Builder::new_from_random_bytes_with_depth(
            Codec::LamportMerkleBlake3256Priv,
            1,
            &mut rng,
        )
        .unwrap()
        .try_build()
        .unwrap();

        let (vlad, advanced) = Builder::default()
            .with_signing_key(&mk)
            .with_message(&test_component_message())
            .try_build_genesis_advance_encoded()
            .unwrap();

        let inner = vlad.to_inner();
        assert_eq!(inner.message()[4], COMPONENT_VERSION_BYTE);
        inner.verify(&advanced).unwrap();
    }
}
