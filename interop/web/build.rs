//! Sets `sqlcipher_vfs_shim` when a CI leg builds a SQLCipher major that encrypts through its own `sqlciphervfs`.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(sqlcipher_vfs_shim)");
    println!("cargo::rerun-if-env-changed=SQLCIPHER_LEG_VERSION");
    let major = std::env::var("SQLCIPHER_LEG_VERSION")
        .ok()
        .and_then(|version| version.split('.').next()?.parse::<u32>().ok());
    if major.is_some_and(|major| major >= 5) {
        println!("cargo::rustc-cfg=sqlcipher_vfs_shim");
    }
}
