//! Key listing + recipient resolution.

use std::collections::HashMap;
use std::sync::Arc;

use super::error::TumpaError;

/// Flat key record returned to Swift. Mirrors the existing Swift
/// `TumpaKeyInfo` shape so the .appex's compose-UI / picker code
/// keeps working unchanged.
#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyInfo {
    /// 40-char uppercase primary fingerprint.
    pub fingerprint: String,
    /// Primary UID's full RFC 822 form
    /// (e.g. `Alice <alice@example.com>`), or the fingerprint as a
    /// fallback when the cert has no UID we can surface.
    pub primary_uid: String,
    /// True iff secret key material is present in the keystore.
    /// Card-backed keys have the public cert only and report `false`.
    pub is_secret: bool,
    /// True iff the keystore has at least one `card_keys` row linking
    /// this fingerprint to a smartcard. The secret material itself is
    /// on the card, not in the keystore — `is_secret` is false for
    /// these keys but unlock / sign / decrypt flows still work via
    /// libtumpa's card-first dispatch. The host's Unlock pane keys
    /// off this slot to surface card-only keys (otherwise they'd be
    /// invisible to a "filter where isSecret == true" check).
    pub has_card: bool,
    pub is_revoked: bool,
    pub is_expired: bool,
}

/// Default conversion. `has_card` is `false` here because the
/// per-key card lookup needs the keystore handle. Use this for
/// callers that surface a signer / inbound-message KeyInfo (where
/// the cert isn't necessarily ours and a card association would
/// be misleading anyway). The list-view path in [`list_keys`] uses
/// [`KeyInfo::from_with_cards`] to populate the slot from the
/// precomputed card-idents map.
impl From<libtumpa::KeyInfo> for KeyInfo {
    fn from(info: libtumpa::KeyInfo) -> Self {
        let empty = std::collections::HashMap::new();
        Self::from_with_cards(info, &empty)
    }
}

impl KeyInfo {
    /// Build a `KeyInfo` from libtumpa's record plus the precomputed
    /// card-association lookup. The lookup is a single-query map
    /// (see [`libtumpa::card::link::card_idents_map`]) populated once
    /// by [`list_keys`]; passing it in keeps `list_keys` at one SQL
    /// round trip even when the keystore has many keys.
    fn from_with_cards(
        info: libtumpa::KeyInfo,
        card_map: &std::collections::HashMap<String, Vec<String>>,
    ) -> Self {
        let primary_uid = info
            .user_ids
            .iter()
            .find(|u| u.is_primary && !u.revoked)
            .or_else(|| info.user_ids.iter().find(|u| !u.revoked))
            .map(|u| u.value.clone())
            .unwrap_or_else(|| info.fingerprint.clone());

        let is_expired = libtumpa::store::key_is_expired(&info);
        let has_card = card_map
            .get(&info.fingerprint)
            .map(|v| !v.is_empty())
            .unwrap_or(false);

        KeyInfo {
            fingerprint: info.fingerprint,
            primary_uid,
            is_secret: info.is_secret,
            has_card,
            is_revoked: info.is_revoked,
            is_expired,
        }
    }
}

/// List every key in the user's tumpa keystore. Honors the
/// `TUMPA_KEYSTORE` env var via [`libtumpa::store::open_keystore`].
///
/// Each `KeyInfo` carries `has_card` derived from the keystore's
/// `card_keys` table — populated via a single
/// [`libtumpa::card::link::card_idents_map`] query rather than a
/// per-key probe, so the cost stays one round trip regardless of
/// keystore size.
#[uniffi::export]
pub fn list_keys() -> Result<Vec<KeyInfo>, TumpaError> {
    let store = libtumpa::store::open_keystore(None)?;
    let keys = store.list_keys().map_err(|e| TumpaError::Keystore {
        message: e.to_string(),
    })?;
    let card_map = libtumpa::card::link::card_idents_map(&store).map_err(|e| {
        TumpaError::Keystore {
            message: format!("card_idents_map: {e}"),
        }
    })?;
    Ok(keys
        .into_iter()
        .map(|k| KeyInfo::from_with_cards(k, &card_map))
        .collect())
}

/// Render a `tcli describe`-shaped multi-line summary of one keystore
/// key for the host UI's "Key details" sheet.
///
/// Output is byte-for-byte identical to `tcli describe <fp>` (same
/// renderer in `libtumpa::describe::format_key_info`), including the
/// trailing `Cards:` block when the keystore has linked card rows for
/// the fingerprint. Returns `InvalidRecipients` when the fingerprint
/// resolves to no key — same shape compose-side recipient lookups use.
#[uniffi::export]
pub fn describe_key(fingerprint: String) -> Result<String, TumpaError> {
    let store = libtumpa::store::open_keystore(None)?;
    let (key_data, key_info) = libtumpa::store::resolve_signer(&store, &fingerprint)?;
    let mut out = libtumpa::describe::format_key_info(&key_data, &key_info);

    let assocs = libtumpa::card::link::card_associations(&store, &key_info.fingerprint)
        .map_err(|e| TumpaError::Keystore {
            message: format!(
                "failed to load card associations for {}: {e}",
                key_info.fingerprint
            ),
        })?;
    libtumpa::describe::append_card_links(&mut out, &assocs);
    Ok(out)
}

/// ASCII-armored full transferable public key for `fingerprint`.
///
/// Used by the Mail extension's "attach my public key when signing"
/// feature, which embeds the bytes as an `application/pgp-keys` MIME
/// part on outbound signed mail (Thunderbird convention,
/// `OpenPGP_0x<long-keyid>.asc`). Unlike
/// [`export_autocrypt_keydata`], the output here is the full cert —
/// every UID, every subkey, all third-party certifications.
#[uniffi::export]
pub fn export_public_armored(fingerprint: String) -> Result<String, TumpaError> {
    let store = libtumpa::store::open_keystore(None)?;
    Ok(libtumpa::key::export_public_armored(&store, &fingerprint)?)
}

/// Autocrypt-minimised transferable public key bytes for `fingerprint`
/// scoped to `addr`. The caller base64-encodes (no line wrap) into the
/// `keydata=` attribute of an outbound `Autocrypt:` header per
/// <https://autocrypt.org/level1.html#openpgp-based-key-data>.
///
/// Output is binary OpenPGP and contains only the primary key, one UID
/// matching `addr` (case-insensitive), the subkey packets with their
/// self-signatures, and the primary's own revocation / direct sigs.
/// Third-party certifications and User Attribute packets are stripped
/// — Autocrypt is per-address and rides on every outbound mail, so
/// size discipline matters and third-party-cert leakage of the social
/// graph would be unacceptable.
#[uniffi::export]
pub fn export_autocrypt_keydata(
    fingerprint: String,
    addr: String,
) -> Result<Vec<u8>, TumpaError> {
    let store = libtumpa::store::open_keystore(None)?;
    Ok(libtumpa::key::export_public_for_autocrypt(
        &store,
        &fingerprint,
        &addr,
    )?)
}

/// Whether a keystore key is usable as a recipient / signer match:
/// not revoked and not expired. Shared by [`resolve_recipients`],
/// [`keys_for_email`], and [`ambiguous_addresses`] so all three apply
/// the same liveness filter.
fn key_is_usable(k: &libtumpa::KeyInfo) -> bool {
    !k.is_revoked && !libtumpa::store::key_is_expired(k)
}

/// Whether any of `key`'s UIDs carries `<email>` (case-insensitive).
/// `email` must already be lowercased by the caller.
fn key_matches_email(k: &libtumpa::KeyInfo, email_lower: &str) -> bool {
    let needle = format!("<{}>", email_lower);
    k.user_ids
        .iter()
        .any(|u| u.value.to_lowercase().contains(&needle))
}

/// Resolve email addresses to fingerprints via the keystore.
///
/// Skips revoked / expired keys (matches today's
/// `TumpaCryptoService.resolveRecipients` filter) so a recipient with
/// only a revoked or expired cert renders as "unresolved" → red dot
/// in compose, never falls through to a confusing INV_RECP at send
/// time.
///
/// When an address matches more than one usable cert this returns the
/// FIRST match (keystore order). The host UI lets the user pin a
/// per-address default via [`keys_for_email`] / [`ambiguous_addresses`];
/// the `.appex` honors that pin before falling back here.
#[uniffi::export]
pub fn resolve_recipients(emails: Vec<String>) -> Result<HashMap<String, String>, TumpaError> {
    let store = Arc::new(libtumpa::store::open_keystore(None)?);
    let all_keys = store.list_keys().map_err(|e| TumpaError::Keystore {
        message: e.to_string(),
    })?;

    let mut out: HashMap<String, String> = HashMap::with_capacity(emails.len());
    for email in emails {
        let needle = email.to_lowercase();
        if let Some(matched) = all_keys
            .iter()
            .find(|k| key_is_usable(k) && key_matches_email(k, &needle))
        {
            out.insert(email, matched.fingerprint.clone());
        }
    }
    Ok(out)
}

/// Every usable (non-revoked, non-expired) cert whose any UID carries
/// `email`. Unlike [`resolve_recipients`], this returns ALL matches,
/// not just the first — the host UI's per-address key picker and the
/// `.appex`'s override-validation both need the full candidate set.
///
/// The flat `KeyInfo` carries `is_secret` / `has_card` so the Swift
/// side can filter to signable certs (signing needs secret material
/// or a linked card) without a second round trip. `has_card` is
/// populated from the same single `card_idents_map` query [`list_keys`]
/// uses.
#[uniffi::export]
pub fn keys_for_email(email: String) -> Result<Vec<KeyInfo>, TumpaError> {
    let store = libtumpa::store::open_keystore(None)?;
    let all_keys = store.list_keys().map_err(|e| TumpaError::Keystore {
        message: e.to_string(),
    })?;
    let card_map = libtumpa::card::link::card_idents_map(&store).map_err(|e| {
        TumpaError::Keystore {
            message: format!("card_idents_map: {e}"),
        }
    })?;

    let needle = email.to_lowercase();
    Ok(all_keys
        .into_iter()
        .filter(|k| key_is_usable(k) && key_matches_email(k, &needle))
        .map(|k| KeyInfo::from_with_cards(k, &card_map))
        .collect())
}

/// Lowercased email addresses that match MORE THAN ONE usable cert —
/// i.e. the addresses where signing / encryption is ambiguous and the
/// host UI should offer a per-address key picker. An address matched
/// by zero or one usable cert is omitted (nothing to choose).
///
/// Emails are collected across every UID of every usable cert, so an
/// address that only appears as a secondary UID still surfaces.
#[uniffi::export]
pub fn ambiguous_addresses() -> Result<Vec<String>, TumpaError> {
    let store = libtumpa::store::open_keystore(None)?;
    let all_keys = store.list_keys().map_err(|e| TumpaError::Keystore {
        message: e.to_string(),
    })?;

    // email (lowercased) -> set of fingerprints carrying it.
    let mut by_email: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    for k in all_keys.iter().filter(|k| key_is_usable(k)) {
        for uid in &k.user_ids {
            if let Some(email) = extract_email(&uid.value) {
                by_email
                    .entry(email)
                    .or_default()
                    .insert(k.fingerprint.clone());
            }
        }
    }

    let mut out: Vec<String> = by_email
        .into_iter()
        .filter(|(_, fps)| fps.len() > 1)
        .map(|(email, _)| email)
        .collect();
    out.sort();
    Ok(out)
}

/// Pull the lowercased `<addr@host>` out of an RFC 822 UID string like
/// `Alice <alice@example.com>`. Returns `None` for UIDs with no
/// angle-bracketed address (bare-name or photo UIDs).
fn extract_email(uid: &str) -> Option<String> {
    let start = uid.find('<')?;
    let end = uid[start + 1..].find('>')? + start + 1;
    let addr = uid[start + 1..end].trim();
    if addr.is_empty() {
        None
    } else {
        Some(addr.to_lowercase())
    }
}
