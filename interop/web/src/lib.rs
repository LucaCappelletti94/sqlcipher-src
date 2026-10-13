//! SQLCipher from `sqlcipher-src` through `sqlite-wasm-rs`'s wrapper, exercised by the tests in `tests/`.

/// SQLCipher release those sources come from, the shipped one unless a CI leg names its own.
pub const SQLCIPHER_VERSION: &str = match option_env!("SQLCIPHER_LEG_VERSION") {
    Some(version) => version,
    None => sqlcipher_src::SQLCIPHER_VERSION,
};
