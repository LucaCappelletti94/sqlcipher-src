//! The generated files agree with the versions the crate declares.

use sqlcipher_src::{
    source_dir, HEADER_FILE, LIBTOMCRYPT_VERSION, SOURCE_FILE, SQLCIPHER_VERSION, SQLITE_VERSION,
};

fn read(file: &str) -> String {
    String::from_utf8_lossy(&std::fs::read(source_dir().join(file)).unwrap()).into_owned()
}

#[test]
fn every_generated_file_is_present() {
    for file in [
        HEADER_FILE,
        SOURCE_FILE,
        "libtomcrypt.c",
        "tomcrypt.h",
        "LICENSE-sqlcipher",
        "LICENSE-libtomcrypt",
        "SHA256SUMS",
    ] {
        assert!(source_dir().join(file).is_file(), "{file} missing");
    }
}

#[test]
fn checksums_cover_every_generated_file() {
    let mut listed: Vec<String> = read("SHA256SUMS")
        .lines()
        .map(|l| l.split_once("  ").unwrap().1.to_owned())
        .collect();
    listed.sort();
    let mut present: Vec<String> = std::fs::read_dir(source_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != "SHA256SUMS")
        .collect();
    present.sort();
    assert_eq!(listed, present);
}

#[test]
fn sources_carry_the_declared_versions() {
    let header = read(HEADER_FILE);
    assert!(header
        .lines()
        .any(|l| l.starts_with("#define SQLITE_VERSION ")
            && l.contains(&format!("\"{SQLITE_VERSION}\""))));
    let sqlcipher = read(SOURCE_FILE);
    assert!(sqlcipher
        .lines()
        .any(|l| l.trim() == format!("#define CIPHER_VERSION_NUMBER {SQLCIPHER_VERSION}")));
    let tomcrypt = read("tomcrypt.h");
    assert!(tomcrypt
        .lines()
        .any(|l| l.starts_with("#define SCRYPT")
            && l.contains(&format!("\"{LIBTOMCRYPT_VERSION}\""))));
}

#[test]
fn crate_version_encodes_the_release() {
    let mut parts = SQLCIPHER_VERSION
        .split('.')
        .map(|p| p.parse::<u64>().unwrap());
    let (major, minor, patch) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let (numbers, metadata) = env!("CARGO_PKG_VERSION").split_once('+').unwrap();
    assert!(
        numbers.starts_with(&format!("{}.{patch}.", major * 100 + minor)),
        "{numbers}"
    );
    assert_eq!(metadata, format!("sqlcipher-{SQLCIPHER_VERSION}-sqlite-{SQLITE_VERSION}-libtomcrypt-{LIBTOMCRYPT_VERSION}"));
}

fn shipped_files() -> Vec<String> {
    std::fs::read_dir(source_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect()
}

fn has_extension(name: &str, extension: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        == Some(extension)
}

#[test]
fn only_upstream_sources_ship() {
    let tomcrypt = read("libtomcrypt.c");
    for name in shipped_files() {
        let source = has_extension(&name, "c") || has_extension(&name, "h");
        assert!(
            source || name.starts_with("LICENSE-") || name == "SHA256SUMS",
            "{name} is not an upstream source"
        );
        // The only C files are the two amalgamations and the tables libtomcrypt includes.
        assert!(
            !has_extension(&name, "c")
                || name == SOURCE_FILE
                || name == "libtomcrypt.c"
                || tomcrypt.contains(&format!("#include \"{name}\"")),
            "{name} is not SQLCipher or libtomcrypt"
        );
    }
}

#[test]
fn sqlcipher_finalizer_is_skipped_on_wasm() {
    let sqlcipher = read(SOURCE_FILE);
    let registration = sqlcipher
        .lines()
        .position(|l| l.contains("section(\".fini_array\")"))
        .expect("SQLCipher no longer registers a .fini_array finalizer, so the patch is obsolete");
    let guard = sqlcipher.lines().nth(registration - 1).unwrap();
    assert_eq!(guard.trim(), "#elif !defined(__wasm__)");
}

#[test]
fn the_finalizer_guard_is_the_only_local_change() {
    for name in shipped_files() {
        let wasm = read(&name)
            .lines()
            .filter(|l| l.contains("__wasm__"))
            .count();
        let expected = usize::from(name == SOURCE_FILE);
        assert_eq!(wasm, expected, "{name} carries a local wasm change");
    }
    // SQLCipher and libtomcrypt reach libtomcrypt's headers through the include path, as released.
    assert!(read(SOURCE_FILE).contains("\n#include <tomcrypt.h>\n"));
    assert!(read("tomcrypt.h").contains("\n#include <tomcrypt_cfg.h>\n"));
    for name in shipped_files().iter().filter(|n| has_extension(n, "h")) {
        assert!(
            !read(name).contains("#include \"tomcrypt"),
            "{name} includes a tomcrypt header by quote, unlike the release"
        );
    }
}
