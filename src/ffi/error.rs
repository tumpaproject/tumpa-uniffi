//! Errors that cross the UniFFI boundary into Swift.

use thiserror::Error;

/// Failure modes for any of the six exported operations.
///
/// Maps to a Swift `enum TumpaError: Error` on the consumer side.
/// The Mail extension's `TumpaCryptoService` translates these into
/// the existing `NSError` reply slots / `addressesFailingEncryption`
/// list, preserving the .appex's wire shape.
#[derive(Debug, Error, uniffi::Error)]
pub enum TumpaError {
    /// One or more recipient strings did not resolve to a usable
    /// public key. The `Vec<String>` carries the offending recipient
    /// IDs so compose-time UI can mark them red. Replaces the
    /// `[GNUPG:] INV_RECP` parsing path that `StatusLineParser` used
    /// to do.
    #[error("invalid recipient(s): {recipients:?}")]
    InvalidRecipients { recipients: Vec<String> },

    /// Smartcard interaction failed (PCSC unavailable, wrong PIN
    /// after `SecretProvider` returned, card removed mid-flow, etc).
    #[error("card error: {message}")]
    Card { message: String },

    /// Keystore I/O / lookup error.
    #[error("keystore error: {message}")]
    Keystore { message: String },

    /// Generic crypto failure (bad signature on the verify path,
    /// software passphrase wrong, malformed ciphertext).
    #[error("crypto error: {message}")]
    Crypto { message: String },

    /// `SecretProvider` returned an error or was cancelled by the
    /// user. Typically pinentry was dismissed / agent socket
    /// unavailable / TUMPA_PASSPHRASE absent and no other source
    /// could supply a secret.
    ///
    /// `fingerprint` and `uid` identify the key that needs
    /// unlocking, so the .appex can render a "needs-unlock for
    /// Alice <a@example.com>" popover with the right key info
    /// pre-filled. Both empty when the wrapper couldn't determine
    /// which key was being asked for (e.g. error path before key
    /// resolution).
    #[error("secret unavailable for {fingerprint}: {message}")]
    SecretUnavailable {
        fingerprint: String,
        uid: String,
        is_pin: bool,
        message: String,
    },
}

/// Map a libtumpa `Error` to our FFI surface. `KeyNotFound` /
/// `UnusableKey` get pulled out as structured `InvalidRecipients` so
/// Swift gets a typed list of failed recipient IDs without re-parsing
/// strings — same job `StatusLineParser.invalidRecipients` did against
/// tclig's `[GNUPG:] INV_RECP` stderr lines.
impl From<libtumpa::Error> for TumpaError {
    fn from(err: libtumpa::Error) -> Self {
        use libtumpa::Error as E;
        match err {
            E::KeyNotFound(id) => TumpaError::InvalidRecipients {
                recipients: vec![id],
            },
            E::UnusableKey { fingerprint, .. } => TumpaError::InvalidRecipients {
                recipients: vec![fingerprint],
            },
            E::CardNotConnected => TumpaError::Card {
                message: "card not connected".into(),
            },
            E::Card(msg) | E::CardUnsupportedAlgorithm { card: msg, .. } => {
                TumpaError::Card { message: msg }
            }
            E::Sign(msg) | E::Verify(msg) | E::Encrypt(msg) | E::Decrypt(msg) => {
                TumpaError::Crypto { message: msg }
            }
            E::KeyStore(msg) | E::InvalidInput(msg) => TumpaError::Keystore { message: msg },
            E::Io(e) => TumpaError::Keystore {
                message: e.to_string(),
            },
            E::Wecanencrypt(e) => TumpaError::Crypto {
                message: e.to_string(),
            },
        }
    }
}
