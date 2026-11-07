//! Sets `sqlcipher_vfs_shim` when a CI leg builds a SQLCipher major that encrypts through its own `sqlciphervfs`, and
//! `sqlcipher_size_hint_salt` when the leg carries sqlcipher#633.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(sqlcipher_vfs_shim)");
    println!("cargo::rustc-check-cfg=cfg(sqlcipher_size_hint_salt)");
    println!("cargo::rerun-if-env-changed=SQLCIPHER_LEG_VERSION");
    println!("cargo::rerun-if-env-changed=SQLCIPHER_LEG");
    let major = std::env::var("SQLCIPHER_LEG_VERSION")
        .ok()
        .and_then(|version| version.split('.').next()?.parse::<u32>().ok());
    if major.is_some_and(|major| major >= 5) {
        println!("cargo::rustc-cfg=sqlcipher_vfs_shim");
    }
    // Only the prerelease head may carry sqlcipher#633, so every other leg and the release skip the salt check.
    if std::env::var("SQLCIPHER_LEG").is_ok_and(|leg| leg == "prerelease") {
        println!("cargo::rustc-cfg=sqlcipher_size_hint_salt");
    }
}
