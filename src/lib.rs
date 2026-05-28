//! UniFFI bindings to libtumpa for the Tumpa Mail macOS extension.
//!
//! Exposes the six operations the Mail extension's XPC service needs:
//! detached signing, sign-then-encrypt (with optional encrypt-only),
//! decrypt+verify, detached verify, list keys, resolve recipients.
//!
//! All secret material (software-key passphrases, smartcard PINs) flows
//! through the [`SecretProvider`] callback interface — libtumpa itself
//! never prompts. The Swift side implements `SecretProvider` and drives
//! pinentry / agent-cache lookup / env-var fallback there.
//!
//! See `tumpa_mail_extension/TumpaCryptoXPC/SecretProvider.swift`.

uniffi::setup_scaffolding!("tumpa");

mod ffi;

pub use ffi::*;
