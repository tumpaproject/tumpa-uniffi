//! Public UniFFI surface. Exported crypto + keystore functions plus
//! the [`SecretProvider`] callback trait.

mod error;
mod keys;
mod ops;
mod secret;
mod types;

pub use error::TumpaError;
pub use keys::{
    ambiguous_addresses, describe_key, export_autocrypt_keydata, export_public_armored,
    keys_for_email, list_keys, resolve_recipients, KeyInfo,
};
pub use ops::{decrypt_and_verify, encrypt, sign_detached, verify_detached};
pub use secret::{SecretProvider, SecretProviderError};
pub use types::{DecryptVerifyOutcome, DecryptVerifyResult, DetachedSignResult, SignBackend, VerifyResult};
