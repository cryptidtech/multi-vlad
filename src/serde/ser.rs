// SPDX-License-Identifier: Apache-2.0
use crate::Vlad;
use multi_trait::EncodeInto;
use serde::ser::{self, SerializeStruct};

/// Serialize instance of [`crate::Vlad`]
impl ser::Serialize for Vlad {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let mut ss = serializer.serialize_struct(crate::vlad::SIGIL.as_str(), 1)?;
            ss.serialize_field("multisig", &self.0)?;
            ss.end()
        } else {
            let v: Vec<u8> = self.encode_into();
            serializer.serialize_bytes(v.as_slice())
        }
    }
}
