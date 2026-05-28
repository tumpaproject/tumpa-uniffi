//! End-to-end smoke test exercising the FFI surface from the Rust
//! side. Uses a stub `SecretProvider` that returns hardcoded secrets;
//! the Swift integration tests will exercise the real
//! pinentry-mac path inside the XPC service.
//!
//! These tests run against a tempdir keystore (TUMPA_KEYSTORE env
//! var) so they don't touch the developer's real ~/.tumpa/keys.db.
//! Cargo runs tests in parallel by default but `serial_test`-style
//! lock isn't needed here because each test creates its own
//! keystore directory.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use tumpa_uniffi::{
    ambiguous_addresses, decrypt_and_verify, describe_key, encrypt, export_autocrypt_keydata,
    export_public_armored, keys_for_email, list_keys, resolve_recipients, sign_detached,
    verify_detached, DecryptVerifyOutcome, SecretProvider, SecretProviderError, VerifyResult,
};

/// Serialize tests that mutate the `TUMPA_KEYSTORE` env var. Cargo
/// runs tests in parallel by default; without this guard, two tests
/// set TUMPA_KEYSTORE concurrently and the second wins for both,
/// pointing one of them at the wrong keystore.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    // `unwrap_or_else(|p| p.into_inner())` recovers from a panicking
    // previous test that poisoned the lock. The lock guards a process-
    // wide env var, not invariant data — so the worst outcome of
    // ignoring the poison is the next test sees an env value set by
    // the panicking one, which is exactly what `fresh_keystore` then
    // overwrites.
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Stub `SecretProvider` that returns whatever the test pre-loaded
/// for a given fingerprint. Mutex-wrapped so tests can hand out
/// `Arc<dyn SecretProvider>` while still mutating the script.
struct ScriptedProvider {
    passphrases: Mutex<std::collections::HashMap<String, Vec<u8>>>,
    /// Records every `cache_verified_secret(fingerprint, is_pin)` call
    /// the wrapper makes after a successful pre-op verify.
    cached: Mutex<Vec<(String, bool)>>,
}

impl ScriptedProvider {
    fn with_passphrase(fp: &str, pw: &str) -> Arc<ScriptedProvider> {
        let mut map = std::collections::HashMap::new();
        map.insert(fp.to_uppercase(), pw.as_bytes().to_vec());
        Arc::new(ScriptedProvider {
            passphrases: Mutex::new(map),
            cached: Mutex::new(Vec::new()),
        })
    }

    /// Snapshot of the (fingerprint, is_pin) pairs the wrapper has
    /// passed to `cache_verified_secret` so far.
    fn cached_calls(&self) -> Vec<(String, bool)> {
        self.cached.lock().unwrap().clone()
    }
}

impl SecretProvider for ScriptedProvider {
    fn passphrase_for_key(
        &self,
        fingerprint: String,
        _uid: String,
    ) -> Result<Vec<u8>, SecretProviderError> {
        self.passphrases
            .lock()
            .unwrap()
            .get(&fingerprint.to_uppercase())
            .cloned()
            .ok_or(SecretProviderError::Cancelled)
    }
    fn pin_for_card(
        &self,
        _card_serial: String,
        _key_fingerprint: String,
        _uid: String,
    ) -> Result<Vec<u8>, SecretProviderError> {
        // Smoke tests run on machines without a card; this branch
        // should never fire because find_signing_card / find_decryption_card
        // return None when no card is connected.
        Err(SecretProviderError::Cancelled)
    }
    fn cache_verified_secret(&self, fingerprint: String, is_pin: bool, _secret: Vec<u8>) {
        self.cached
            .lock()
            .unwrap()
            .push((fingerprint.to_uppercase(), is_pin));
    }
}

/// Set up a fresh keystore in a tempdir, point TUMPA_KEYSTORE at it,
/// and return the dir handle + the env-lock guard so the env var
/// stays valid for the duration of the test. The directory is
/// removed by the `TempDir` Drop.
fn fresh_keystore() -> (tempfile::TempDir, PathBuf, MutexGuard<'static, ()>) {
    let guard = env_lock();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.db");
    std::env::set_var("TUMPA_KEYSTORE", &path);
    (dir, path, guard)
}

fn import(path: &PathBuf, pkt: &[u8]) -> String {
    // Import via wecanencrypt directly; libtumpa::key::import_any
    // also works but pulls in more deps.
    let store = wecanencrypt::KeyStore::open(path).expect("open keystore");
    store.import_key(pkt).expect("import key")
}

#[test]
fn describe_key_returns_tcli_describe_text() {
    // Pins the FFI surface used by the host UI's "Key details" sheet.
    // Renderer is shared with `tcli describe`, so any drift in the
    // libtumpa output rolls into both surfaces.
    let (_dir, path, _env) = fresh_keystore();
    let alice =
        wecanencrypt::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
    let fp = import(&path, &alice.secret_key);

    let out = describe_key(fp.clone()).expect("describe_key");
    assert!(out.starts_with("sec  "), "header: {out}");
    assert!(out.contains(&fp));
    assert!(out.contains("Alice <alice@example.com>"));
    assert!(out.contains("[primary]"));
    assert!(out.contains("Subkeys:"));
}

#[test]
fn describe_key_for_unknown_fingerprint_errors() {
    let (_dir, _path, _env) = fresh_keystore();
    let bogus = "0000000000000000000000000000000000000000".to_string();
    let err = describe_key(bogus).expect_err("must error on unknown fp");
    // libtumpa's KeyNotFound flows into our InvalidRecipients variant.
    use tumpa_uniffi::TumpaError;
    assert!(matches!(err, TumpaError::InvalidRecipients { .. }), "got: {err:?}");
}

#[test]
fn list_keys_returns_imported_keys() {
    let (_dir, path, _env) = fresh_keystore();
    let alice = wecanencrypt::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
    let _fp = import(&path, &alice.secret_key);

    let keys = list_keys().expect("list_keys");
    assert_eq!(keys.len(), 1);
    assert!(keys[0].is_secret);
    // No card linked; the host's Unlock pane filter
    // `(isSecret || hasCard)` works for software keys via the
    // is_secret half. hasCard is only true after `tcli card link`
    // wires up a smartcard.
    assert!(!keys[0].has_card);
    assert!(!keys[0].is_revoked);
    assert!(!keys[0].is_expired);
    assert!(keys[0].primary_uid.contains("alice@example.com"));
}

#[test]
fn resolve_recipients_matches_email() {
    let (_dir, path, _env) = fresh_keystore();
    let alice = wecanencrypt::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
    let fp = import(&path, &alice.secret_key);

    let resolved = resolve_recipients(vec!["alice@example.com".into(), "bogus@nope.invalid".into()])
        .expect("resolve_recipients");
    assert_eq!(resolved.get("alice@example.com"), Some(&fp));
    assert_eq!(resolved.get("bogus@nope.invalid"), None);
}

#[test]
fn keys_for_email_returns_every_match() {
    // Two distinct certs sharing the same email — the ambiguity the
    // per-address picker exists to resolve. keys_for_email must return
    // BOTH (resolve_recipients only returns the first).
    let (_dir, path, _env) = fresh_keystore();
    let a = wecanencrypt::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
    let b = wecanencrypt::create_key_simple("pw", &["Alice (work) <alice@example.com>"]).unwrap();
    let fp_a = import(&path, &a.secret_key);
    let fp_b = import(&path, &b.secret_key);
    assert_ne!(fp_a, fp_b);

    let matches = keys_for_email("alice@example.com".into()).expect("keys_for_email");
    let fps: std::collections::HashSet<String> =
        matches.iter().map(|k| k.fingerprint.clone()).collect();
    assert_eq!(fps.len(), 2);
    assert!(fps.contains(&fp_a) && fps.contains(&fp_b));

    // Case-insensitive and a non-matching address yields nothing.
    assert_eq!(
        keys_for_email("ALICE@EXAMPLE.COM".into()).unwrap().len(),
        2
    );
    assert!(keys_for_email("bogus@nope.invalid".into())
        .unwrap()
        .is_empty());
}

#[test]
fn ambiguous_addresses_lists_only_multi_key_emails() {
    let (_dir, path, _env) = fresh_keystore();
    // alice@ has two certs → ambiguous; bob@ has one → not.
    let a1 = wecanencrypt::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
    let a2 = wecanencrypt::create_key_simple("pw", &["Alice 2 <alice@example.com>"]).unwrap();
    let bob = wecanencrypt::create_key_simple("pw", &["Bob <bob@example.com>"]).unwrap();
    import(&path, &a1.secret_key);
    import(&path, &a2.secret_key);
    import(&path, &bob.secret_key);

    let ambiguous = ambiguous_addresses().expect("ambiguous_addresses");
    assert_eq!(ambiguous, vec!["alice@example.com".to_string()]);
}

#[test]
fn sign_detached_then_verify_detached_roundtrip() {
    let (_dir, path, _env) = fresh_keystore();
    let alice = wecanencrypt::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
    let fp = import(&path, &alice.secret_key);

    let provider = ScriptedProvider::with_passphrase(&fp, "pw");
    let result = sign_detached(
        b"hello, world".to_vec(),
        fp.clone(),
        Some("SHA256".into()),
        provider.clone(),
    )
    .expect("sign");

    assert!(!result.armored.is_empty());
    assert!(result.armored.starts_with(b"-----BEGIN PGP SIGNATURE-----"));

    // The wrapper must call cache_verified_secret exactly once, with
    // is_pin=false (this is a software-key test) and the same
    // fingerprint we asked it to sign with.
    let calls = provider.cached_calls();
    assert_eq!(
        calls,
        vec![(fp.to_uppercase(), false)],
        "expected exactly one passphrase cache hand-off after verify"
    );

    let verified = verify_detached(b"hello, world".to_vec(), result.armored).expect("verify");
    match verified {
        VerifyResult::Good {
            verifier_fingerprint,
            signer,
        } => {
            assert_eq!(verifier_fingerprint.len(), 40);
            assert!(verifier_fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(signer.primary_uid.contains("alice@example.com"));
        }
        other => panic!("expected Good, got {other:?}"),
    }
}

#[test]
fn encrypt_and_decrypt_roundtrip_with_inner_signature() {
    let (_dir, path, _env) = fresh_keystore();
    let alice = wecanencrypt::create_key_simple("alice-pw", &["Alice <alice@example.com>"]).unwrap();
    let bob = wecanencrypt::create_key_simple("bob-pw", &["Bob <bob@example.com>"]).unwrap();
    let alice_fp = import(&path, &alice.secret_key);
    let _bob_fp = import(&path, &bob.secret_key);

    // Sign-then-encrypt with Alice as signer to Bob as recipient.
    let provider = ScriptedProvider::with_passphrase(&alice_fp, "alice-pw");
    let ct = encrypt(
        b"signed and sealed".to_vec(),
        vec!["bob@example.com".into()],
        Vec::new(),
        Some(alice_fp.clone()),
        true,
        Some(provider),
    )
    .expect("encrypt");
    assert!(!ct.is_empty());

    // Decrypt+verify on Bob's side. Bob's pw, Alice's pubkey already
    // in the keystore from the import.
    let bob_fp = wecanencrypt::parse_key_bytes(&bob.secret_key, true)
        .unwrap()
        .fingerprint;
    let bob_provider = ScriptedProvider::with_passphrase(&bob_fp, "bob-pw");
    let result = decrypt_and_verify(ct, bob_provider).expect("decrypt+verify");
    assert_eq!(result.plaintext, b"signed and sealed");
    match result.outcome {
        DecryptVerifyOutcome::Good {
            signer,
            verifier_fingerprint,
        } => {
            assert!(signer.primary_uid.contains("alice@example.com"));
            assert_eq!(verifier_fingerprint.len(), 40);
        }
        other => panic!("expected Good, got {other:?}"),
    }
}

#[test]
fn encrypt_only_decrypts_to_unsigned() {
    let (_dir, path, _env) = fresh_keystore();
    let alice = wecanencrypt::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
    let fp = import(&path, &alice.secret_key);

    // No signer.
    let ct = encrypt(
        b"plain".to_vec(),
        vec!["alice@example.com".into()],
        Vec::new(),
        None,
        true,
        None,
    )
    .expect("encrypt");

    let provider = ScriptedProvider::with_passphrase(&fp, "pw");
    let result = decrypt_and_verify(ct, provider).expect("decrypt+verify");
    assert_eq!(result.plaintext, b"plain");
    assert!(matches!(result.outcome, DecryptVerifyOutcome::Unsigned));
}

/// `hidden_recipients` route through the libtumpa `*_with_hidden`
/// entry points and the resulting ciphertext is decryptable by the
/// hidden recipient. The byte-level throw-keyid wildcard assertion
/// (all-zero PKESK key id) lives in libtumpa's own tests — this FFI
/// smoke test pins the plumbing.
///
/// Encrypts to ONLY a hidden recipient (no visible) so the test
/// focuses on the hidden-only code path through the FFI. The
/// visible-and-hidden combination is exercised by the libtumpa-level
/// tests; here we'd otherwise be testing rpgp's trial-decrypt order
/// against a multi-PKESK ciphertext, which is out of scope.
#[test]
fn encrypt_hidden_only_round_trips_for_the_hidden_recipient() {
    let (_dir, path, _env) = fresh_keystore();
    let charlie =
        wecanencrypt::create_key_simple("c-pw", &["Charlie <charlie@example.com>"]).unwrap();
    let charlie_fp = import(&path, &charlie.secret_key);

    // No visible recipients, one hidden recipient (Charlie). No signer.
    let ct = encrypt(
        b"hidden-only payload".to_vec(),
        Vec::new(),
        vec!["charlie@example.com".into()],
        None,
        true,
        None,
    )
    .expect("encrypt");
    assert!(!ct.is_empty());

    let prov = ScriptedProvider::with_passphrase(&charlie_fp, "c-pw");
    let out = decrypt_and_verify(ct, prov).expect("charlie decrypt");
    assert_eq!(out.plaintext, b"hidden-only payload");
}

/// `export_autocrypt_keydata` returns non-empty binary OpenPGP. Round
/// trip through wecanencrypt's keystore import: the bytes are a
/// well-formed transferable public key with the matching primary
/// fingerprint. (libtumpa's own tests cover the UID-minimisation and
/// User-Attribute-stripping rules.)
#[test]
fn export_autocrypt_keydata_returns_parseable_minimised_cert() {
    let (_dir, path, _env) = fresh_keystore();
    let alice = wecanencrypt::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
    let fp = import(&path, &alice.secret_key);

    let keydata = export_autocrypt_keydata(fp.clone(), "alice@example.com".into())
        .expect("export_autocrypt_keydata");
    assert!(!keydata.is_empty(), "Autocrypt keydata must not be empty");

    // Bytes parse back to a public-cert KeyInfo whose primary
    // fingerprint matches the source key.
    let parsed = wecanencrypt::parse_key_bytes(&keydata, false).expect("parse minimised cert");
    assert_eq!(
        parsed.fingerprint.to_uppercase(),
        fp.to_uppercase(),
        "Autocrypt-minimised export must carry the same primary fingerprint"
    );
    assert!(
        !parsed.is_secret,
        "Autocrypt export is public-only by construction"
    );
}

/// `export_public_armored` returns a full ASCII-armored transferable
/// public key — `-----BEGIN PGP PUBLIC KEY BLOCK-----` framed and
/// parseable back through the keystore.
#[test]
fn export_public_armored_round_trip() {
    let (_dir, path, _env) = fresh_keystore();
    let alice = wecanencrypt::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
    let fp = import(&path, &alice.secret_key);

    let armored = export_public_armored(fp.clone()).expect("export_public_armored");
    assert!(
        armored.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
        "armored header missing: {}",
        &armored[..armored.len().min(80)]
    );
    assert!(armored
        .trim_end()
        .ends_with("-----END PGP PUBLIC KEY BLOCK-----"));

    let parsed =
        wecanencrypt::parse_key_bytes(armored.as_bytes(), false).expect("parse armored cert");
    assert_eq!(parsed.fingerprint.to_uppercase(), fp.to_uppercase());
    assert!(!parsed.is_secret);
}

#[test]
fn encrypt_to_unknown_recipient_fails_with_invalid_recipients() {
    let (_dir, _path, _env) = fresh_keystore();
    let err = encrypt(
        b"hi".to_vec(),
        vec!["nobody@example.invalid".into()],
        Vec::new(),
        None,
        true,
        None,
    )
    .expect_err("should fail");
    let msg = err.to_string();
    assert!(
        msg.contains("invalid recipient"),
        "expected InvalidRecipients error, got: {msg}"
    );
}
