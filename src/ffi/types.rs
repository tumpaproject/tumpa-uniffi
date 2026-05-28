//! Result types crossing the FFI boundary.
//!
//! These mirror libtumpa's domain types but are flattened / reshaped
//! to keep the Swift surface simple and to avoid carrying types UniFFI
//! doesn't represent natively (`DateTime`, nested `KeyAlgorithm`
//! enums, `Zeroizing<Vec<u8>>`).

/// Which signing backend produced a signature.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum SignBackend {
    /// Signed on a connected smartcard.
    Card,
    /// Signed with a software secret key from the keystore.
    Software,
}

impl From<libtumpa::sign::SignBackend> for SignBackend {
    fn from(b: libtumpa::sign::SignBackend) -> Self {
        match b {
            libtumpa::sign::SignBackend::Card => SignBackend::Card,
            libtumpa::sign::SignBackend::Software => SignBackend::Software,
        }
    }
}

/// Result of `sign_detached`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DetachedSignResult {
    /// ASCII-armored detached signature ready to drop into a
    /// `multipart/signed` PGP/MIME body.
    pub armored: Vec<u8>,
    /// Hash algorithm name suitable for the `micalg` parameter
    /// (`"SHA256"`, `"SHA512"`, etc.).
    pub hash_algorithm: String,
    /// Whether the card or the software key produced this signature.
    pub backend: SignBackend,
}

/// Result of `decrypt_and_verify`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DecryptVerifyResult {
    /// Decrypted bytes. Caller is responsible for memory hygiene
    /// once they cross into Swift; the Rust side has already
    /// zeroized any `Zeroizing<...>` containers it held.
    pub plaintext: Vec<u8>,
    pub outcome: DecryptVerifyOutcome,
}

/// Inner-signature classification on a decrypt+verify outcome.
///
/// Mirrors `libtumpa::decrypt::DecryptVerifyOutcome` but with `KeyInfo`
/// flattened to the fields the Mail extension's `MEMessageSigner`
/// actually needs.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum DecryptVerifyOutcome {
    /// Encrypt-only payload — no inner signature.
    Unsigned,
    /// Inner signature present and verified.
    Good {
        signer: super::keys::KeyInfo,
        /// Full 40-char fingerprint of the key that actually signed
        /// (may be a signing subkey, not the primary). This is the
        /// VALIDSIG-shaped value the security popover should display.
        verifier_fingerprint: String,
    },
    /// Inner signature present, signer key in keystore, but the
    /// signature did not verify.
    Bad { signer: super::keys::KeyInfo },
    /// Inner signature present but the signer's public key isn't in
    /// the keystore. `issuer_ids` carries 16-char key IDs and/or
    /// 40-char fingerprints from the signature packet.
    UnknownKey { issuer_ids: Vec<String> },
}

/// Result of `verify_detached`. Distinct from
/// [`DecryptVerifyOutcome`] only in that there's no `Unsigned` case
/// — the caller hands us a signature, so a result of "no signature"
/// is impossible.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum VerifyResult {
    Good {
        signer: super::keys::KeyInfo,
        verifier_fingerprint: String,
    },
    Bad {
        signer: super::keys::KeyInfo,
    },
    UnknownKey {
        /// 16-char key ID from the signature packet — the value
        /// `[GNUPG:] GOODSIG` would have carried.
        key_id: String,
    },
}
