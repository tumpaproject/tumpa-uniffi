//! The four crypto operations: detached sign, encrypt (with optional
//! sign), decrypt+verify, detached verify.
//!
//! Each wrapper opens a fresh `KeyStore` per call (matches today's
//! per-spawn-tclig model) and adapts the [`SecretProvider`] callback
//! into libtumpa's closure-driven entry points.

use std::sync::Arc;

use std::sync::Mutex;

use libtumpa::sign::{Secret, SecretRequest};
use libtumpa::{Passphrase, Pin};

use super::error::TumpaError;
use super::secret::{SecretProvider, SecretProviderError};
use super::types::{
    DecryptVerifyOutcome, DecryptVerifyResult, DetachedSignResult, SignBackend, VerifyResult,
};

/// Hand-off slot the closure-driven `secret_for_request` populates
/// when the foreign `SecretProvider` returns an error. libtumpa
/// flattens the closure error into an `Error::Sign(...)` /
/// `Error::Decrypt(...)` string by the time we see it again — but
/// we want to surface the structured "needs-unlock" info to Swift,
/// so we tee it through this side channel.
struct LastSecretFailure {
    fingerprint: String,
    uid: String,
    is_pin: bool,
}

// Translate libtumpa's `SecretRequest` callback parameter into a
// concrete dispatch onto our foreign `SecretProvider`. The
// `secret_for_request` helper is what the closures in each wrapper
// invoke to bridge the two shapes.
//
// In addition to fetching the secret, this runs the smartcard-safe
// pre-op verify step: a single `wecanencrypt::card::verify_user_pin`
// APDU for cards, or `wecanencrypt::verify_software_passphrase` for
// software keys. Verify failure routes through `failure_sink` so the
// outer wrapper raises `SecretUnavailable` and the foreign side
// re-prompts; verify success calls
// `provider.cache_verified_secret`, which the foreign side uses to
// `PUT_PASSPHRASE` the now-known-correct value into the agent.
//
// `signer_key_data` is the secret-key bytes the wrapper resolved
// from the keystore; needed for the software-key verify (which
// unlocks the secret-key packet without doing the real op).
fn secret_for_request(
    provider: &Arc<dyn SecretProvider>,
    failure_sink: &Mutex<Option<LastSecretFailure>>,
    signer_key_data: &[u8],
    req: SecretRequest<'_>,
) -> libtumpa::Result<Secret> {
    let primary_uid = |info: &libtumpa::KeyInfo| -> String {
        info.user_ids
            .iter()
            .find(|u| u.is_primary && !u.revoked)
            .or_else(|| info.user_ids.iter().find(|u| !u.revoked))
            .map(|u| u.value.clone())
            .unwrap_or_else(|| info.fingerprint.clone())
    };

    match req {
        SecretRequest::CardPin {
            card_ident,
            key_info,
        } => {
            let fp = key_info.fingerprint.clone();
            let uid = primary_uid(key_info);
            let pin_bytes = provider
                .pin_for_card(card_ident.to_string(), fp.clone(), uid.clone())
                .map_err(|e| {
                    *failure_sink.lock().unwrap() = Some(LastSecretFailure {
                        fingerprint: fp.clone(),
                        uid: uid.clone(),
                        is_pin: true,
                    });
                    secret_err_to_libtumpa(e)
                })?;

            // Pre-op verify: bare VERIFY APDU. On wrong PIN the card
            // counter decrements once and we surface "needs-unlock"
            // immediately, before the real sign / decrypt op spends
            // its own round-trip.
            if let Err(e) = wecanencrypt::card::verify_user_pin(&pin_bytes, Some(card_ident)) {
                *failure_sink.lock().unwrap() = Some(LastSecretFailure {
                    fingerprint: fp,
                    uid,
                    is_pin: true,
                });
                return Err(libtumpa::Error::Sign(format!(
                    "card PIN verification failed: {e}"
                )));
            }

            // Verified — broadcast to the foreign cache so subsequent
            // calls for this key skip the prompt.
            provider.cache_verified_secret(fp, true, pin_bytes.clone());

            Ok(Secret::Pin(Pin::new(pin_bytes)))
        }
        SecretRequest::KeyPassphrase { key_info } => {
            let fp = key_info.fingerprint.clone();
            let uid = primary_uid(key_info);
            let pw_bytes = provider
                .passphrase_for_key(fp.clone(), uid.clone())
                .map_err(|e| {
                    *failure_sink.lock().unwrap() = Some(LastSecretFailure {
                        fingerprint: fp.clone(),
                        uid: uid.clone(),
                        is_pin: false,
                    });
                    secret_err_to_libtumpa(e)
                })?;
            // libtumpa's Passphrase is Zeroizing<String>. UTF-8 invalid
            // input is the caller's bug — surface it as a Sign error so
            // the wrapper's `?` lifts it out without panicking.
            let s = String::from_utf8(pw_bytes.clone()).map_err(|e| {
                libtumpa::Error::Sign(format!("non-UTF-8 passphrase: {e}"))
            })?;

            // Pre-op verify: try to unlock the secret-key packet.
            if let Err(e) = wecanencrypt::verify_software_passphrase(signer_key_data, &s) {
                *failure_sink.lock().unwrap() = Some(LastSecretFailure {
                    fingerprint: fp,
                    uid,
                    is_pin: false,
                });
                return Err(libtumpa::Error::Sign(format!(
                    "passphrase verification failed: {e}"
                )));
            }

            provider.cache_verified_secret(fp, false, pw_bytes);

            Ok(Secret::Passphrase(Passphrase::new(s)))
        }
    }
}

fn secret_err_to_libtumpa(e: SecretProviderError) -> libtumpa::Error {
    libtumpa::Error::Sign(format!("secret provider: {e}"))
}

/// If `failure_sink` was populated during this call, replace
/// whatever generic libtumpa error the wrapper saw with a structured
/// `SecretUnavailable` carrying the fingerprint+uid.
fn enrich_secret_error(
    err: TumpaError,
    failure_sink: &Mutex<Option<LastSecretFailure>>,
) -> TumpaError {
    if let Some(f) = failure_sink.lock().unwrap().take() {
        TumpaError::SecretUnavailable {
            fingerprint: f.fingerprint,
            uid: f.uid,
            is_pin: f.is_pin,
            message: err.to_string(),
        }
    } else {
        err
    }
}

/// Detached sign `body` with the secret key whose primary fingerprint
/// is `signer_fingerprint`. Returns the armored signature plus the
/// hash algorithm actually used (for the `multipart/signed` `micalg`
/// parameter) plus the backend (card vs software).
///
/// Card-first dispatch is internal to libtumpa: when a connected
/// card's signing slot matches the requested key, the card produces
/// the signature; otherwise we fall back to the software secret (and
/// `provider.passphrase_for_key` is invoked).
#[uniffi::export]
pub fn sign_detached(
    body: Vec<u8>,
    signer_fingerprint: String,
    digest: Option<String>,
    provider: Arc<dyn SecretProvider>,
) -> Result<DetachedSignResult, TumpaError> {
    let store = libtumpa::store::open_keystore(None)?;
    let (key_data, key_info) = libtumpa::store::resolve_signer(&store, &signer_fingerprint)?;

    let hash_pref = match digest {
        Some(d) => Some(libtumpa::sign::parse_digest_algo(&d)?),
        None => None,
    };

    let failure_sink: Mutex<Option<LastSecretFailure>> = Mutex::new(None);
    let result = libtumpa::sign::sign_detached_with_hash(
        &key_data,
        &key_info,
        &body,
        hash_pref,
        |req| secret_for_request(&provider, &failure_sink, &key_data, req),
    )
    .map_err(|e| enrich_secret_error(TumpaError::from(e), &failure_sink))?;

    Ok(DetachedSignResult {
        armored: result.armored.into_bytes(),
        hash_algorithm: format!("{:?}", result.hash_algorithm).to_uppercase(),
        backend: SignBackend::from(result.backend),
    })
}

/// Encrypt `plaintext` to a split visible / hidden recipient set.
///
/// `recipients` are visible (To/Cc): their key id is exposed in the
/// PKESK header. `hidden_recipients` are encoded with the RFC 4880
/// throw-keyid wildcard (all-zero key id), so a visible recipient
/// running `gpg --list-packets` on the ciphertext cannot enumerate
/// the hidden (Bcc) set.
///
/// If `signer_fingerprint` is `Some`, the message is sign-then-encrypted
/// (one-pass-signature inside the ciphertext). Card-first dispatch on
/// the signing leg is implemented here in the wrapper — libtumpa exposes
/// the software and card paths as separate fns and leaves the dispatch
/// to callers.
///
/// When `hidden_recipients` is empty the call routes to the original
/// non-hidden libtumpa entry points (matches the pre-0.4 behavior).
#[uniffi::export]
pub fn encrypt(
    plaintext: Vec<u8>,
    recipients: Vec<String>,
    hidden_recipients: Vec<String>,
    signer_fingerprint: Option<String>,
    armor: bool,
    provider: Option<Arc<dyn SecretProvider>>,
) -> Result<Vec<u8>, TumpaError> {
    let store = libtumpa::store::open_keystore(None)?;
    let recipient_refs: Vec<&str> = recipients.iter().map(|s| s.as_str()).collect();
    let hidden_refs: Vec<&str> = hidden_recipients.iter().map(|s| s.as_str()).collect();
    let has_hidden = !hidden_refs.is_empty();

    match signer_fingerprint {
        None => {
            if has_hidden {
                Ok(libtumpa::encrypt::encrypt_to_recipients_with_hidden(
                    &store,
                    &recipient_refs,
                    &hidden_refs,
                    &plaintext,
                    armor,
                )?)
            } else {
                Ok(libtumpa::encrypt::encrypt_to_recipients(
                    &store,
                    &recipient_refs,
                    &plaintext,
                    armor,
                )?)
            }
        }
        Some(fp) => {
            let provider = provider.ok_or_else(|| TumpaError::Crypto {
                message: "sign+encrypt requested without a SecretProvider".into(),
            })?;
            let (signer_key_data, signer_info) = libtumpa::store::resolve_signer(&store, &fp)?;

            let primary_uid = signer_info
                .user_ids
                .iter()
                .find(|u| u.is_primary && !u.revoked)
                .map(|u| u.value.clone())
                .unwrap_or_else(|| signer_info.fingerprint.clone());

            // Card-first: if a connected card's signing slot matches
            // this signer, sign-then-encrypt on the card.
            if let Some(card_match) =
                libtumpa::encrypt::find_signing_card_for_encrypt(&signer_key_data)
                    .unwrap_or(None)
            {
                let pin_bytes = provider
                    .pin_for_card(
                        card_match.card.ident.clone(),
                        signer_info.fingerprint.clone(),
                        primary_uid.clone(),
                    )
                    .map_err(|e| TumpaError::SecretUnavailable {
                        fingerprint: signer_info.fingerprint.clone(),
                        uid: primary_uid.clone(),
                        is_pin: true,
                        message: e.to_string(),
                    })?;

                // Pre-op verify: bare VERIFY APDU.
                wecanencrypt::card::verify_user_pin(&pin_bytes, Some(&card_match.card.ident))
                    .map_err(|e| TumpaError::SecretUnavailable {
                        fingerprint: signer_info.fingerprint.clone(),
                        uid: primary_uid.clone(),
                        is_pin: true,
                        message: format!("card PIN verification failed: {e}"),
                    })?;

                // Verified — cache for subsequent calls.
                provider.cache_verified_secret(
                    signer_info.fingerprint.clone(),
                    true,
                    pin_bytes.clone(),
                );

                let pin = Pin::new(pin_bytes);
                if has_hidden {
                    return Ok(
                        libtumpa::encrypt::sign_and_encrypt_on_card_to_recipients_with_hidden(
                            &store,
                            &signer_key_data,
                            &pin,
                            Some(&card_match.card.ident),
                            &recipient_refs,
                            &hidden_refs,
                            &plaintext,
                            armor,
                        )?,
                    );
                } else {
                    return Ok(
                        libtumpa::encrypt::sign_and_encrypt_on_card_to_recipients(
                            &store,
                            &signer_key_data,
                            &pin,
                            Some(&card_match.card.ident),
                            &recipient_refs,
                            &plaintext,
                            armor,
                        )?,
                    );
                }
            }

            // Software fallback. Resolve the passphrase via the
            // provider and call the software sign+encrypt path.
            let pw_bytes = provider
                .passphrase_for_key(signer_info.fingerprint.clone(), primary_uid.clone())
                .map_err(|e| TumpaError::SecretUnavailable {
                    fingerprint: signer_info.fingerprint.clone(),
                    uid: primary_uid.clone(),
                    is_pin: false,
                    message: e.to_string(),
                })?;
            let pw_str = String::from_utf8(pw_bytes.clone()).map_err(|e| TumpaError::Crypto {
                message: format!("non-UTF-8 passphrase: {e}"),
            })?;

            // Pre-op verify: secret-key unlock without any crypto op.
            wecanencrypt::verify_software_passphrase(&signer_key_data, &pw_str).map_err(|e| {
                TumpaError::SecretUnavailable {
                    fingerprint: signer_info.fingerprint.clone(),
                    uid: primary_uid.clone(),
                    is_pin: false,
                    message: format!("passphrase verification failed: {e}"),
                }
            })?;

            provider.cache_verified_secret(signer_info.fingerprint.clone(), false, pw_bytes);

            let passphrase = Passphrase::new(pw_str);
            if has_hidden {
                Ok(libtumpa::encrypt::sign_and_encrypt_to_recipients_with_hidden(
                    &store,
                    &signer_key_data,
                    &passphrase,
                    &recipient_refs,
                    &hidden_refs,
                    &plaintext,
                    armor,
                )?)
            } else {
                Ok(libtumpa::encrypt::sign_and_encrypt_to_recipients(
                    &store,
                    &signer_key_data,
                    &passphrase,
                    &recipient_refs,
                    &plaintext,
                    armor,
                )?)
            }
        }
    }
}

/// Decrypt+verify in one call. Returns plaintext plus a typed
/// signature outcome — the caller does NOT have to parse `[GNUPG:]`
/// status lines anymore.
///
/// Card-first dispatch: if a connected card's encryption slot
/// matches the ciphertext recipients, the card decrypts the session
/// key (and we invoke `provider.pin_for_card`). Otherwise we fall
/// back to a software secret key (and invoke
/// `provider.passphrase_for_key`).
#[uniffi::export]
pub fn decrypt_and_verify(
    ciphertext: Vec<u8>,
    provider: Arc<dyn SecretProvider>,
) -> Result<DecryptVerifyResult, TumpaError> {
    let store = libtumpa::store::open_keystore(None)?;

    // Card-first.
    if let Some(card) =
        libtumpa::decrypt::find_decryption_card(&store, &ciphertext).unwrap_or(None)
    {
        let primary_uid = card
            .key_info
            .user_ids
            .iter()
            .find(|u| u.is_primary && !u.revoked)
            .map(|u| u.value.clone())
            .unwrap_or_else(|| card.key_info.fingerprint.clone());
        let pin_bytes = provider
            .pin_for_card(
                card.card.ident.clone(),
                card.key_info.fingerprint.clone(),
                primary_uid.clone(),
            )
            .map_err(|e| TumpaError::SecretUnavailable {
                fingerprint: card.key_info.fingerprint.clone(),
                uid: primary_uid.clone(),
                is_pin: true,
                message: e.to_string(),
            })?;

        // Pre-op verify: bare VERIFY APDU. Wrong PIN errors out as
        // SecretUnavailable so Mail re-prompts via fallback.
        wecanencrypt::card::verify_user_pin(&pin_bytes, Some(&card.card.ident)).map_err(
            |e| TumpaError::SecretUnavailable {
                fingerprint: card.key_info.fingerprint.clone(),
                uid: primary_uid.clone(),
                is_pin: true,
                message: format!("card PIN verification failed: {e}"),
            },
        )?;

        provider.cache_verified_secret(
            card.key_info.fingerprint.clone(),
            true,
            pin_bytes.clone(),
        );

        let pin = Pin::new(pin_bytes);
        let result = libtumpa::decrypt::decrypt_and_verify_on_card(
            &store,
            &card.key_data,
            &ciphertext,
            &pin,
            Some(&card.card.ident),
        )?;
        return Ok(libtumpa_result_to_ffi(result));
    }

    // Software path.
    //
    // First pass: ID-matched lookup. The keystore is indexed by key
    // id, so a PKESK carrying a non-zero recipient key id locates the
    // matching secret directly.
    //
    // Fallback for throw-keyid PKESKs: when the sender used the
    // RFC 4880 wildcard (all-zero recipient key id) to hide a Bcc'd
    // recipient, ID-matched lookup returns None even though one of
    // the keystore's secret keys actually decrypts the message.
    // libtumpa::decrypt::find_software_decryption_key only does
    // ID-matched lookup, so we hand-roll a trial-decrypt fallback
    // against the user's secret keys here in the FFI layer.
    // Common case for Mail: keystore holds exactly one secret (the
    // user's own), so "trial decrypt" is just "try the only key."
    let (key_data, key_info) = match libtumpa::decrypt::find_software_decryption_key(
        &store,
        &ciphertext,
    )? {
        Some(pair) => pair,
        None => find_decryption_key_by_trial(&store, &ciphertext, &provider)?
            .ok_or_else(|| TumpaError::Crypto {
                message: "no decryption key available for this ciphertext".into(),
            })?,
    };
    let primary_uid = key_info
        .user_ids
        .iter()
        .find(|u| u.is_primary && !u.revoked)
        .map(|u| u.value.clone())
        .unwrap_or_else(|| key_info.fingerprint.clone());
    let pw_bytes = provider
        .passphrase_for_key(key_info.fingerprint.clone(), primary_uid.clone())
        .map_err(|e| TumpaError::SecretUnavailable {
            fingerprint: key_info.fingerprint.clone(),
            uid: primary_uid.clone(),
            is_pin: false,
            message: e.to_string(),
        })?;
    let pw_str = String::from_utf8(pw_bytes.clone()).map_err(|e| TumpaError::Crypto {
        message: format!("non-UTF-8 passphrase: {e}"),
    })?;

    // Pre-op verify: secret-key unlock.
    wecanencrypt::verify_software_passphrase(&key_data, &pw_str).map_err(|e| {
        TumpaError::SecretUnavailable {
            fingerprint: key_info.fingerprint.clone(),
            uid: primary_uid.clone(),
            is_pin: false,
            message: format!("passphrase verification failed: {e}"),
        }
    })?;

    provider.cache_verified_secret(key_info.fingerprint.clone(), false, pw_bytes);

    let passphrase = Passphrase::new(pw_str);
    let result =
        libtumpa::decrypt::decrypt_and_verify_with_key(&store, &key_data, &ciphertext, &passphrase)?;
    Ok(libtumpa_result_to_ffi(result))
}

/// Trial-decryption fallback for throw-keyid PKESKs.
///
/// When `libtumpa::decrypt::find_software_decryption_key` returns
/// `None`, the ciphertext either (a) wasn't encrypted to any key in
/// the store, or (b) was encrypted to a hidden (Bcc) recipient whose
/// PKESK carries the all-zero throw-keyid wildcard. Case (b) is what
/// Mail extension users hit when they're the Bcc'd recipient on an
/// incoming encrypted message — libtumpa's ID-matched lookup never
/// matches the wildcard, so we'd otherwise reject perfectly
/// decryptable mail.
///
/// Strategy: iterate every secret key in the keystore (including
/// card-linked keys whose secret lives on hardware — those are
/// `is_secret == false` but the runtime keeps card-first dispatch up
/// the stack, so software trial here is correct: we only try keys
/// whose secret material is actually present in the keystore). For
/// each candidate, fetch the passphrase via the provider and call
/// rpgp's `Message::decrypt` (through `wecanencrypt::decrypt_bytes`).
/// First key that produces plaintext wins.
///
/// Provider-error handling: if the provider returns Cancelled /
/// errors for one key we move on to the next. Only after every
/// candidate fails do we surface the "no decryption key" error.
/// This matches the rule that a wrong passphrase on key A shouldn't
/// stop us trying key B.
///
/// Cost: the keystore size in Mail's typical case is 1–3 secrets;
/// trial-decryption is fast (one session-key unwrap per attempt).
/// The fallback runs only when ID-matched lookup misses, so
/// id-tagged PKESKs (the common case) skip this entirely.
fn find_decryption_key_by_trial(
    store: &wecanencrypt::KeyStore,
    ciphertext: &[u8],
    provider: &Arc<dyn SecretProvider>,
) -> Result<Option<(Vec<u8>, libtumpa::KeyInfo)>, TumpaError> {
    let all = store.list_keys().map_err(|e| TumpaError::Keystore {
        message: format!("list_keys: {e}"),
    })?;
    for info in all.into_iter().filter(|k| k.is_secret) {
        let (data, _) = match store.get_key(&info.fingerprint) {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        let primary_uid = info
            .user_ids
            .iter()
            .find(|u| u.is_primary && !u.revoked)
            .map(|u| u.value.clone())
            .unwrap_or_else(|| info.fingerprint.clone());
        let pw_bytes = match provider.passphrase_for_key(info.fingerprint.clone(), primary_uid.clone()) {
            Ok(b) => b,
            // Provider cancelled / errored — try the next secret.
            Err(_) => continue,
        };
        let pw_str = match String::from_utf8(pw_bytes.clone()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // wecanencrypt::decrypt_bytes goes straight through rpgp's
        // Message::decrypt, which trial-decrypts the throw-keyid PKESK
        // against the supplied secret. If the session key unwraps
        // successfully we have the right secret; rpgp returns
        // plaintext bytes. We discard those here — the outer caller
        // re-decrypts via `decrypt_and_verify_with_key` to get the
        // signature outcome too — but the successful unwrap is proof
        // this is the right key.
        if wecanencrypt::decrypt_bytes(&data, ciphertext, &pw_str).is_ok() {
            provider.cache_verified_secret(info.fingerprint.clone(), false, pw_bytes);
            return Ok(Some((data, info)));
        }
    }
    Ok(None)
}

fn libtumpa_result_to_ffi(r: libtumpa::decrypt::DecryptVerifyResult) -> DecryptVerifyResult {
    let outcome = match r.outcome {
        libtumpa::decrypt::DecryptVerifyOutcome::Unsigned => DecryptVerifyOutcome::Unsigned,
        libtumpa::decrypt::DecryptVerifyOutcome::Good {
            key_info,
            verifier_fingerprint,
        } => DecryptVerifyOutcome::Good {
            signer: super::keys::KeyInfo::from(key_info),
            verifier_fingerprint,
        },
        libtumpa::decrypt::DecryptVerifyOutcome::Bad { key_info } => DecryptVerifyOutcome::Bad {
            signer: super::keys::KeyInfo::from(key_info),
        },
        libtumpa::decrypt::DecryptVerifyOutcome::UnknownKey { issuer_ids } => {
            DecryptVerifyOutcome::UnknownKey { issuer_ids }
        }
    };
    // Clone the plaintext out of the Zeroizing<Vec<u8>> container so
    // the original buffer zeroes on drop. The clone we hand back is
    // NOT zeroized — UniFFI copies it across the FFI into a Swift
    // `Data` and Swift owns memory hygiene from there. The Mail
    // extension's caller passes plaintext on to MEDecodedMessage and
    // Mail's caches; trying to zero it on this side wouldn't help.
    let plaintext: Vec<u8> = (*r.plaintext).clone();
    DecryptVerifyResult { plaintext, outcome }
}

/// Verify a detached signature over `signed_bytes`. Returns one of
/// `Good { signer, verifier_fingerprint }` (where
/// `verifier_fingerprint` is the 40-char value the popover should
/// display, equivalent to tclig's `[GNUPG:] VALIDSIG` line),
/// `Bad { signer }`, or `UnknownKey { key_id }`.
#[uniffi::export]
pub fn verify_detached(
    signed_bytes: Vec<u8>,
    signature: Vec<u8>,
) -> Result<VerifyResult, TumpaError> {
    let store = libtumpa::store::open_keystore(None)?;
    let outcome = libtumpa::verify::verify_detached(&store, &signed_bytes, &signature)?;
    Ok(match outcome {
        libtumpa::verify::VerifyOutcome::Good {
            key_info,
            verifier_fingerprint,
        } => VerifyResult::Good {
            signer: super::keys::KeyInfo::from(key_info),
            verifier_fingerprint,
        },
        libtumpa::verify::VerifyOutcome::Bad { key_info } => VerifyResult::Bad {
            signer: super::keys::KeyInfo::from(key_info),
        },
        libtumpa::verify::VerifyOutcome::UnknownKey { key_id } => VerifyResult::UnknownKey { key_id },
    })
}
