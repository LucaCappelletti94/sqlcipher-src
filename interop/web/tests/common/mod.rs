//! Files exchanged with the native harness under Node, and the settings that let an older native SQLCipher read them.
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(module = "fs")]
extern "C" {
    #[wasm_bindgen(js_name = readFileSync)]
    pub fn read_file_sync(path: &str) -> Vec<u8>;
    #[wasm_bindgen(js_name = writeFileSync)]
    pub fn write_file_sync(path: &str, data: &[u8]);
}

pub const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures");

fn major(version: &str) -> u32 {
    version
        .split('.')
        .next()
        .and_then(|major| major.parse().ok())
        .unwrap_or_else(|| panic!("no major version in {version:?}"))
}

/// `key` followed by the `cipher_compatibility` of the native harness's SQLCipher when that is an older major,
/// so files cross in the format the native side reads and writes by default.
///
/// # Panics
///
/// When the native harness has not written a readable `native-version` into the fixtures.
#[must_use]
pub fn keyed(key: &str) -> String {
    let native = String::from_utf8(read_file_sync(&format!("{DIR}/native-version"))).unwrap();
    let native = major(&native);
    if native < major(interop_web::SQLCIPHER_VERSION) {
        format!("{key}; PRAGMA cipher_compatibility = {native};")
    } else {
        key.to_owned()
    }
}
