//! rusqlite on `wasm32-unknown-unknown` gets SQLCipher from this crate with no rusqlite feature enabled.
use rusqlite::Connection;
use sqlite_wasm_rs::vfs::memvfs::MemVfsUtil;
use sqlite_wasm_rs::vfs::transfer::DbTransfer;
use wasm_bindgen_test::wasm_bindgen_test;

pub mod common;
use common::{keyed, read_file_sync, write_file_sync, DIR};

const RAW: &str =
    "PRAGMA key = \"x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'\"";
const PASS: &str = "PRAGMA key = 'correct horse battery staple'";
const REKEY_PASS: &str = "PRAGMA rekey = 'correct horse battery staple'";
const REKEY_RAW: &str =
    "PRAGMA rekey = \"x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'\"";

fn open(name: &str, key: &str) -> Connection {
    let db = Connection::open(name).unwrap();
    db.execute_batch(&keyed(key)).unwrap();
    db
}

#[wasm_bindgen_test]
fn rusqlite_reads_native_and_writes_for_native() {
    let version = Connection::open_in_memory()
        .unwrap()
        .query_row("PRAGMA cipher_version", [], |r| r.get::<_, String>(0))
        .unwrap();
    assert!(
        version.starts_with(&format!("{} ", interop_web::SQLCIPHER_VERSION)),
        "{version}"
    );
    let util = unsafe { MemVfsUtil::get() }.unwrap();
    for (name, key) in [("native-raw.db", RAW), ("native-pass.db", PASS)] {
        util.import_db_unchecked(name, &read_file_sync(&format!("{DIR}/{name}")))
            .unwrap();
        let v: String = open(name, key)
            .query_row("SELECT v FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, "written natively");
        let wrong = open(name, "PRAGMA key = 'wrong'");
        assert!(
            wrong
                .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r
                    .get::<_, i64>(0))
                .is_err(),
            "{name} opened with a wrong key"
        );
    }
    for (name, key) in [("rusqlite-raw.db", RAW), ("rusqlite-pass.db", PASS)] {
        open(name, key)
            .execute_batch(
                "CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('written in the browser');",
            )
            .unwrap();
        let bytes = util.export_db(name).unwrap();
        assert!(
            !bytes.starts_with(b"SQLite format 3"),
            "{name} is not encrypted"
        );
        assert!(
            !bytes.windows(22).any(|w| w == b"written in the browser"),
            "{name} leaks plaintext"
        );
        write_file_sync(&format!("{DIR}/{name}"), &bytes);
    }
}

#[wasm_bindgen_test]
fn rusqlite_rekey_from_raw_to_pass() {
    // SAFETY: the memvfs is registered during rusqlite's library initialisation, which
    // occurs when the wasm module is loaded, before any test executes.
    let util = unsafe { MemVfsUtil::get() }.unwrap();
    util.import_db_unchecked(
        "rl-rekey-raw.db",
        &read_file_sync(&format!("{DIR}/native-rekey-raw.db")),
    )
    .unwrap();
    {
        let conn = Connection::open("rl-rekey-raw.db").unwrap();
        conn.execute_batch(&keyed(RAW)).unwrap();
        conn.execute_batch(REKEY_PASS).unwrap();
    }
    let bytes = util.export_db("rl-rekey-raw.db").unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "rl-rekey-raw.db is not encrypted after rekey to passphrase"
    );
    write_file_sync(&format!("{DIR}/rusqlite-rekey-to-pass.db"), &bytes);
}

#[wasm_bindgen_test]
fn rusqlite_rekey_from_pass_to_raw() {
    // SAFETY: same invariant as rusqlite_rekey_from_raw_to_pass — memvfs is registered
    // at module load time before any test runs.
    let util = unsafe { MemVfsUtil::get() }.unwrap();
    util.import_db_unchecked(
        "rl-rekey-pass.db",
        &read_file_sync(&format!("{DIR}/native-rekey-pass.db")),
    )
    .unwrap();
    {
        let conn = Connection::open("rl-rekey-pass.db").unwrap();
        conn.execute_batch(&keyed(PASS)).unwrap();
        conn.execute_batch(REKEY_RAW).unwrap();
    }
    let bytes = util.export_db("rl-rekey-pass.db").unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "rl-rekey-pass.db is not encrypted after rekey to raw key"
    );
    write_file_sync(&format!("{DIR}/rusqlite-rekey-to-raw.db"), &bytes);
}

#[wasm_bindgen_test]
fn rusqlite_compat3() {
    // SAFETY: memvfs is registered at module load time before any test runs.
    let util = unsafe { MemVfsUtil::get() }.unwrap();
    util.import_db_unchecked(
        "rl-compat3.db",
        &read_file_sync(&format!("{DIR}/native-compat3-pass.db")),
    )
    .unwrap();
    {
        let conn = Connection::open("rl-compat3.db").unwrap();
        // `cipher_compatibility` only applies once `PRAGMA key` has created the codec.
        conn.execute_batch(
            "PRAGMA key = 'correct horse battery staple'; PRAGMA cipher_compatibility = 3;",
        )
        .unwrap();
        let v: String = conn.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(
            v, "written natively",
            "compat3 read from native file returned unexpected value"
        );
    }
    {
        let conn = Connection::open("rl-compat3.db").unwrap();
        // PRAGMA key alone uses this build's defaults, which cannot decrypt a compat3 file.
        conn.execute_batch(PASS).unwrap();
        assert!(
            conn.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r
                .get::<_, i64>(0))
                .is_err(),
            "compat3 db decrypted without cipher_compatibility=3; settings had no effect"
        );
    }
    {
        let conn = Connection::open("rl-compat3-write.db").unwrap();
        conn.execute_batch(
            "PRAGMA key = 'correct horse battery staple'; PRAGMA cipher_compatibility = 3;",
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('written in the browser');",
        )
        .unwrap();
    }
    let bytes = util.export_db("rl-compat3-write.db").unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "rl-compat3-write.db is not encrypted"
    );
    write_file_sync(&format!("{DIR}/rusqlite-compat3-pass.db"), &bytes);
}

#[wasm_bindgen_test]
fn rusqlite_cipher_integrity_check() {
    // SAFETY: memvfs is registered at module load time before any test runs.
    let util = unsafe { MemVfsUtil::get() }.unwrap();
    for (name, key) in [("native-raw.db", RAW), ("native-pass.db", PASS)] {
        let vfs_name = format!("rl-ic-{name}");
        util.import_db_unchecked(&vfs_name, &read_file_sync(&format!("{DIR}/{name}")))
            .unwrap();
        let conn = Connection::open(&vfs_name).unwrap();
        conn.execute_batch(&keyed(key)).unwrap();
        let rows: Vec<String> = conn
            .prepare("PRAGMA cipher_integrity_check")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            rows.is_empty(),
            "{name} cipher_integrity_check reported errors: {rows:?}"
        );
    }
}
