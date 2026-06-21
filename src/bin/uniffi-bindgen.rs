//! Bindings generator. Run e.g.:
//!   cargo run --bin uniffi-bindgen -- generate --library \
//!     target/release/libconstruct_transport.dylib --language swift --out-dir bindings
fn main() {
    uniffi::uniffi_bindgen_main()
}
