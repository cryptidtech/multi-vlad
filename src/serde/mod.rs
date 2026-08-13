// SPDX-License-Identifier: Apache-2.0
//! Serde (de)serialization for [`crate::Vlad`]
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::vlad;
    use multi_key::{EncodedMultikey, Multikey};
    use multi_trait::Null;

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
    fn test_vlad_serde_encoded_string() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad = vlad::Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build_encoded()
            .unwrap();

        // roundtrip: encode to string, decode back, compare
        let s = vlad.to_string();
        let decoded = vlad::EncodedVlad::try_from(s.as_str()).unwrap();
        assert_eq!(vlad, decoded);
    }

    #[test]
    fn test_vlad_serde_json() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad = vlad::Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build()
            .unwrap();

        // roundtrip through JSON
        let s = serde_json::to_string(&vlad).unwrap();
        let deserialized: vlad::Vlad = serde_json::from_str(&s).unwrap();
        assert_eq!(vlad, deserialized);

        // verify the JSON structure contains "multisig" field
        let json: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(
            json.get("multisig").is_some(),
            "JSON should have 'multisig' field"
        );
    }

    #[cfg(not(feature = "dag_cbor"))]
    #[test]
    fn test_vlad_serde_cbor() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad = vlad::Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build()
            .unwrap();

        // roundtrip through CBOR
        let v = multi_cbor::to_vec(&vlad).unwrap();
        let deserialized: vlad::Vlad = multi_cbor::from_slice(&v).unwrap();
        assert_eq!(vlad, deserialized);
    }

    #[cfg(feature = "dag_cbor")]
    #[test]
    fn test_vlad_serde_dag_cbor() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad = vlad::Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build()
            .unwrap();

        // roundtrip through CBOR (dag_cbor feature)
        let v = multi_cbor::to_vec(&vlad).unwrap();
        let deserialized: vlad::Vlad = multi_cbor::from_slice(&v).unwrap();
        assert_eq!(vlad, deserialized);
    }

    #[test]
    fn test_null_vlad_serde_compact() {
        let v = vlad::Vlad::null();
        // roundtrip through binary serialization
        let bytes: Vec<u8> = v.clone().into();
        let deserialized = vlad::Vlad::try_from(bytes.as_ref()).unwrap();
        assert_eq!(v, deserialized);

        // also verify CBOR roundtrip
        let cbor = multi_cbor::to_vec(&v).unwrap();
        let from_cbor: vlad::Vlad = multi_cbor::from_slice(&cbor).unwrap();
        assert_eq!(v, from_cbor);
    }

    #[test]
    fn test_null_vlad_serde_readable() {
        let v = vlad::Vlad::null();
        // roundtrip through JSON (human-readable)
        let s = serde_json::to_string(&v).unwrap();
        let deserialized: vlad::Vlad = serde_json::from_str(&s).unwrap();
        assert_eq!(v, deserialized);

        // verify the JSON structure
        let json: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(
            json.get("multisig").is_some(),
            "null Vlad JSON should have 'multisig' field"
        );
    }

    #[test]
    fn test_encoded_null_vlad_serde_readable() {
        let v: vlad::EncodedVlad = vlad::Vlad::null().into();
        // roundtrip through encoded string
        let s = v.to_string();
        let decoded = vlad::EncodedVlad::try_from(s.as_str()).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn test_vlad_serde_verify_after_roundtrip() {
        let mk = test_signing_key();
        let msg = test_wasm_message();

        let vlad = vlad::Builder::default()
            .with_signing_key(&mk)
            .with_message(&msg)
            .try_build()
            .unwrap();

        // verify original
        vlad.verify(&mk).unwrap();

        // roundtrip through JSON and verify again
        let s = serde_json::to_string(&vlad).unwrap();
        let deserialized: vlad::Vlad = serde_json::from_str(&s).unwrap();
        deserialized.verify(&mk).unwrap();

        // roundtrip through CBOR and verify again
        let v = multi_cbor::to_vec(&vlad).unwrap();
        let from_cbor: vlad::Vlad = multi_cbor::from_slice(&v).unwrap();
        from_cbor.verify(&mk).unwrap();
    }
}
