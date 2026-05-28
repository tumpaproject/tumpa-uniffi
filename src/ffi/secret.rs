//! `SecretProvider` callback interface — the Rust side of the
//! pinentry bridge. Swift implements this in
//! `tumpa_mail_extension/TumpaCryptoXPC/SecretProvider.swift`.

use thiserror::Error;

/// Foreign-implemented callback that supplies a software-key
/// passphrase or a smartcard PIN when libtumpa needs one.
///
/// Resolution order on the Swift side:
///
/// 1. `~/.tumpa/agent.sock` `GET_OR_PROMPT` — cache lookup, falling
///    back to the agent's pinentry on a desktop session, or
///    `PINENTRY_UNAVAILABLE` on a headless one.
/// 2. Local fallback paths the foreign side may implement
///    (env vars, in-app SwiftUI popovers, terminal prompts).
///
/// Returned bytes are wrapped in `Zeroizing` immediately on the Rust
/// side and passed to libtumpa as `&Passphrase` / `&Pin`. After a
/// successful verify-then-real-op in the Rust wrapper, the wrapper
/// calls [`SecretProvider::cache_verified_secret`] so the foreign
/// side can `PUT_PASSPHRASE` the now-known-correct secret to the
/// agent (or no-op if it was already cached).
#[uniffi::export(with_foreign)]
pub trait SecretProvider: Send + Sync {
    /// Software-key passphrase. `fingerprint` is the 40-char
    /// uppercase primary fingerprint; `uid` is the human-readable
    /// primary UID (e.g. `Alice <alice@example.com>`) for display in
    /// the pinentry dialog.
    fn passphrase_for_key(
        &self,
        fingerprint: String,
        uid: String,
    ) -> Result<Vec<u8>, SecretProviderError>;

    /// Smartcard user PIN. `card_serial` is the card's
    /// `MANUFACTURER:SERIAL` ident, `key_fingerprint` is the
    /// fingerprint of the key on the card whose unlock is being
    /// requested, `uid` is the primary UID for display.
    fn pin_for_card(
        &self,
        card_serial: String,
        key_fingerprint: String,
        uid: String,
    ) -> Result<Vec<u8>, SecretProviderError>;

    /// Notify the foreign provider that `secret` was verified correct
    /// for the key identified by `fingerprint` (PIN if `is_pin` is
    /// true, software-key passphrase otherwise).
    ///
    /// The wrapper calls this immediately after a successful verify
    /// step (smartcard `VERIFY` APDU or sequoia secret-key unlock)
    /// and BEFORE the real crypto op. The provider should `PUT` the
    /// secret into the tumpa agent cache so subsequent calls for the
    /// same key skip the prompt.
    ///
    /// Returns nothing — cache write failures should not abort the
    /// in-flight crypto op. The provider is free to no-op (e.g. when
    /// the secret already came from the agent cache).
    fn cache_verified_secret(&self, fingerprint: String, is_pin: bool, secret: Vec<u8>);
}

/// Errors a [`SecretProvider`] implementation may signal back to
/// libtumpa.
#[derive(Debug, Error, uniffi::Error)]
pub enum SecretProviderError {
    /// User dismissed pinentry / no source could supply the secret.
    /// libtumpa should NOT retry against another backend after this.
    #[error("user cancelled")]
    Cancelled,

    /// pinentry / agent socket / env-var lookup failed in a way the
    /// caller should surface as an error rather than silently fall
    /// through.
    #[error("secret provider failure: {message}")]
    Internal { message: String },
}
