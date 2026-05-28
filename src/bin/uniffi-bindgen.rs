// In-tree uniffi-bindgen so a fresh checkout doesn't need a separately
// installed `uniffi-bindgen` binary. Invoked by
// `tumpa_mail_extension/scripts/regen-uniffi-bindings.sh` as
// `cargo run --release --bin uniffi-bindgen -- generate --library
// <cdylib path> --language swift --out-dir <Generated/>`.

fn main() {
    uniffi::uniffi_bindgen_main()
}
