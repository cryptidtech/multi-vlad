// SPDX-License-Identifier: Apache-2.0
use crate::Vlad;
use core::fmt;
use multi_sig::Multisig;
use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer,
};

/// Deserialize instance of [`crate::Vlad`]
impl<'de> Deserialize<'de> for Vlad {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["multisig"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Multisig,
        }

        struct VladVisitor;

        impl<'de> Visitor<'de> for VladVisitor {
            type Value = Vlad;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "struct Vlad")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Vlad, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut multisig = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Multisig => {
                            if multisig.is_some() {
                                return Err(Error::duplicate_field("multisig"));
                            }
                            let ms: Multisig = map.next_value()?;
                            multisig = Some(ms);
                        }
                    }
                }
                let multisig = multisig.ok_or_else(|| Error::missing_field("multisig"))?;
                let vlad = Vlad(multisig);
                vlad.validate().map_err(|e| Error::custom(e.to_string()))?;
                Ok(vlad)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct(crate::vlad::SIGIL.as_str(), FIELDS, VladVisitor)
        } else {
            let b: &'de [u8] = Deserialize::deserialize(deserializer)?;
            Ok(Self::try_from(b).map_err(|e| Error::custom(e.to_string()))?)
        }
    }
}
