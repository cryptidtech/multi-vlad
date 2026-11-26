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
    /// The message of a Vlad passes the `\0asm` magic check but is not the
    /// WASM component form of a first-lock script: the version byte that
    /// follows the magic is not the `0x0d` component version byte
    ///
    /// Rebuild the message from the log's component-form first-lock script
    /// and build the Vlad again.
    #[error("a vlad message is not the component form")]
    ScriptForm,
    /// A genesis Vlad's first-lock WASM does not carry the multiproof
    /// verifier form of the root lock script mandate
    ///
    /// A multiproof-era genesis installs the root pattern: the root key path
    /// carries exactly one multiproof verifier script, which is a WASM
    /// component. The log-foot genesis authorizes its foot entry under the
    /// VLAD first lock, so the genesis Vlad's message is that root lock
    /// script and must be the component form.
    ///
    /// The parse and builder paths now report [`VladError::ScriptForm`] for
    /// a message that misses the component form. This variant stays
    /// reserved for the genesis first-lock duty.
    #[error("genesis Vlad first-lock WASM does not carry the multiproof verifier component form of the root pattern")]
    RootPattern,
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
    fn test_root_pattern_error() {
        let err = Error::Vlad(VladError::RootPattern);
        assert_eq!(err.kind(), "Vlad");
        assert_eq!(
            err.to_string(),
            "genesis Vlad first-lock WASM does not carry the multiproof verifier component form of the root pattern"
        );
    }

    #[test]
    fn test_script_form_error() {
        let err = Error::Vlad(VladError::ScriptForm);
        assert_eq!(err.kind(), "Vlad");
        assert_eq!(err.to_string(), "a vlad message is not the component form");
    }

    #[test]
    fn test_error_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<Error>();
        assert_sync::<Error>();
    }
}
