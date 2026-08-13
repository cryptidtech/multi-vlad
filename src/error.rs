// SPDX-License-Identifier: Apache-2.0

/// Errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A multicodec decoding error
    #[error(transparent)]
    Multicodec(#[from] multi_codec::Error),
    /// A multikey error
    #[error(transparent)]
    Multikey(#[from] multi_key::Error),
    /// A multisig error
    #[error(transparent)]
    Multisig(#[from] multi_sig::Error),
    /// Vlad error
    #[error(transparent)]
    Vlad(#[from] VladError),
}

/// Vlad Errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VladError {
    /// Missing sigil 0x07
    #[error("Missing Vlad sigil")]
    MissingSigil,
    /// Missing signing key
    #[error("Missing signing key")]
    MissingSigningKey,
    /// Missing message
    #[error("Missing message")]
    MissingMessage,
    /// Multisig is not a combined signature (message is empty)
    #[error("Vlad Multisig is not a combined signature")]
    NotCombined,
    /// Message does not contain valid WASM binary (missing \0asm magic)
    #[error("Vlad message is not valid WASM binary")]
    InvalidWasm,
}

impl Error {
    /// Get the error kind as a string
    #[must_use]
    pub const fn kind(&self) -> &str {
        match self {
            Self::Multicodec(_) => "Multicodec",
            Self::Multikey(_) => "Multikey",
            Self::Multisig(_) => "Multisig",
            Self::Vlad(_) => "Vlad",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_kind() {
        let err = Error::Vlad(VladError::MissingSigil);
        assert_eq!(err.kind(), "Vlad");
    }

    #[test]
    fn test_error_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<Error>();
        assert_sync::<Error>();
    }
}
