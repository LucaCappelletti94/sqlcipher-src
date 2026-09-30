#![doc = include_str!("../README.md")]

use std::path::Path;

/// SQLCipher release the vendored amalgamation is generated from.
pub const SQLCIPHER_VERSION: &str = "4.19.0";

/// SQLite release that SQLCipher release is based on.
pub const SQLITE_VERSION: &str = "3.53.4";

/// libtomcrypt release providing the ciphers, hashes and random generator.
pub const LIBTOMCRYPT_VERSION: &str = "1.18.2";

/// SQLCipher amalgamation inside [`source_dir`], with the crypto provider left to the build.
pub const SOURCE_FILE: &str = "sqlcipher.c";

/// Public SQLCipher header inside [`source_dir`].
pub const HEADER_FILE: &str = "sqlite3.h";

/// Directory holding the sources, at the path this crate was compiled from.
#[must_use]
pub fn source_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/sqlcipher"))
}
