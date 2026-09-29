//! SQLCipher on the in-memory VFS, with nothing that needs Node, so browsers run it too.
use rusqlite::Connection;
use sqlite_wasm_rs as ffi;
use sqlite_wasm_rs::vfs::memvfs::MemVfsUtil;
use sqlite_wasm_rs::vfs::transfer::DbTransfer;
use sqlite_wasm_rs::vfs::VfsFilesManager;
use std::ffi::{CStr, CString};
use wasm_bindgen_test::wasm_bindgen_test;

const RAW: &str =
    "PRAGMA key = \"x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'\"";
const PASS: &str = "PRAGMA key = 'correct horse battery staple'";

struct Db(*mut ffi::sqlite3);

impl Db {
    fn open(name: &str) -> Self {
        let name = CString::new(name).unwrap();
        let mut db = std::ptr::null_mut();
        let flags = ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE;
        assert_eq!(
            unsafe { ffi::sqlite3_open_v2(name.as_ptr(), &raw mut db, flags, std::ptr::null()) },
            ffi::SQLITE_OK,
            "sqlite3_open_v2 failed"
        );
        Self(db)
    }

    /// First column of the first row, or the error message.
    fn one(&self, sql: &str) -> Result<Option<String>, String> {
        let sql = CString::new(sql).unwrap();
        let mut stmt = std::ptr::null_mut();
        unsafe {
            if ffi::sqlite3_prepare_v2(
                self.0,
                sql.as_ptr(),
                -1,
                &raw mut stmt,
                std::ptr::null_mut(),
            ) != ffi::SQLITE_OK
            {
                return Err(CStr::from_ptr(ffi::sqlite3_errmsg(self.0))
                    .to_string_lossy()
                    .into_owned());
            }
            let r = match ffi::sqlite3_step(stmt) {
                ffi::SQLITE_ROW => {
                    let t = ffi::sqlite3_column_text(stmt, 0);
                    Ok((!t.is_null())
                        .then(|| CStr::from_ptr(t.cast()).to_string_lossy().into_owned()))
                }
                ffi::SQLITE_DONE => Ok(None),
                _ => Err(CStr::from_ptr(ffi::sqlite3_errmsg(self.0))
                    .to_string_lossy()
                    .into_owned()),
            };
            ffi::sqlite3_finalize(stmt);
            r
        }
    }

    fn exec(&self, sql: &str) {
        let sql = CString::new(sql).unwrap();
        let rc = unsafe {
            ffi::sqlite3_exec(
                self.0,
                sql.as_ptr(),
                None,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, ffi::SQLITE_OK, "{:?}", unsafe {
            CStr::from_ptr(ffi::sqlite3_errmsg(self.0))
        });
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        unsafe { ffi::sqlite3_close(self.0) };
    }
}

fn memvfs() -> MemVfsUtil {
    assert_eq!(
        unsafe { ffi::sqlite3_initialize() },
        ffi::SQLITE_OK,
        "sqlite3_initialize failed"
    );
    unsafe { MemVfsUtil::get() }.unwrap()
}

#[wasm_bindgen_test]
fn sqlcipher_version_and_provider() {
    memvfs();
    let db = Db::open("enc-probe.db");
    db.exec(RAW);
    let v = db.one("PRAGMA cipher_version").unwrap();
    let p = db.one("PRAGMA cipher_provider").unwrap();
    assert!(
        v.as_deref()
            .is_some_and(|v| v.starts_with(&format!("{} ", interop_web::SQLCIPHER_VERSION))),
        "unexpected cipher_version: {v:?}"
    );
    assert_eq!(
        p.as_deref(),
        Some("libtomcrypt"),
        "unexpected cipher_provider: {p:?}"
    );
}

#[wasm_bindgen_test]
fn ffi_encrypted_raw_key() {
    let util = memvfs();
    {
        let db = Db::open("enc-ffi-raw.db");
        db.exec(RAW);
        db.exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('browser encrypted');");
    }
    let bytes = util.export_db("enc-ffi-raw.db").unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "enc-ffi-raw.db is not encrypted"
    );
    assert!(
        !bytes.windows(17).any(|w| w == b"browser encrypted"),
        "enc-ffi-raw.db leaks plaintext"
    );
    util.import_db_unchecked("enc-ffi-raw-check.db", &bytes)
        .unwrap();
    let db = Db::open("enc-ffi-raw-check.db");
    db.exec(RAW);
    assert_eq!(
        db.one("SELECT v FROM t").unwrap().as_deref(),
        Some("browser encrypted"),
        "enc-ffi-raw-check.db row mismatch"
    );
    let wrong = Db::open("enc-ffi-raw-check.db");
    wrong.exec("PRAGMA key = 'wrong'");
    assert!(
        wrong.one("SELECT count(*) FROM sqlite_schema").is_err(),
        "enc-ffi-raw-check.db must reject wrong key"
    );
}

#[wasm_bindgen_test]
fn ffi_encrypted_passphrase() {
    let util = memvfs();
    {
        let db = Db::open("enc-ffi-pass.db");
        db.exec(PASS);
        db.exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('browser encrypted');");
    }
    let bytes = util.export_db("enc-ffi-pass.db").unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "enc-ffi-pass.db is not encrypted"
    );
    assert!(
        !bytes.windows(17).any(|w| w == b"browser encrypted"),
        "enc-ffi-pass.db leaks plaintext"
    );
    util.import_db_unchecked("enc-ffi-pass-check.db", &bytes)
        .unwrap();
    let db = Db::open("enc-ffi-pass-check.db");
    db.exec(PASS);
    assert_eq!(
        db.one("SELECT v FROM t").unwrap().as_deref(),
        Some("browser encrypted"),
        "enc-ffi-pass-check.db row mismatch"
    );
    let wrong = Db::open("enc-ffi-pass-check.db");
    wrong.exec("PRAGMA key = 'wrong'");
    assert!(
        wrong.one("SELECT count(*) FROM sqlite_schema").is_err(),
        "enc-ffi-pass-check.db must reject wrong key"
    );
}

#[wasm_bindgen_test]
fn rusqlite_encrypted_raw_key() {
    let util = memvfs();
    {
        let db = Connection::open("enc-rl-raw.db").unwrap();
        db.execute_batch(RAW).unwrap();
        db.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('browser encrypted');")
            .unwrap();
    }
    let bytes = util.export_db("enc-rl-raw.db").unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "enc-rl-raw.db is not encrypted"
    );
    assert!(
        !bytes.windows(17).any(|w| w == b"browser encrypted"),
        "enc-rl-raw.db leaks plaintext"
    );
    util.import_db_unchecked("enc-rl-raw-check.db", &bytes)
        .unwrap();
    util.import_db_unchecked("enc-rl-raw-wrong.db", &bytes)
        .unwrap();
    let v: String = {
        let db = Connection::open("enc-rl-raw-check.db").unwrap();
        db.execute_batch(RAW).unwrap();
        db.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap()
    };
    assert_eq!(v, "browser encrypted", "enc-rl-raw-check.db row mismatch");
    let wrong = Connection::open("enc-rl-raw-wrong.db").unwrap();
    wrong.execute_batch("PRAGMA key = 'wrong'").unwrap();
    assert!(
        wrong
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r
                .get::<_, i64>(0))
            .is_err(),
        "enc-rl-raw-wrong.db must reject wrong key"
    );
}

#[wasm_bindgen_test]
fn rusqlite_encrypted_passphrase() {
    let util = memvfs();
    {
        let db = Connection::open("enc-rl-pass.db").unwrap();
        db.execute_batch(PASS).unwrap();
        db.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('browser encrypted');")
            .unwrap();
    }
    let bytes = util.export_db("enc-rl-pass.db").unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "enc-rl-pass.db is not encrypted"
    );
    assert!(
        !bytes.windows(17).any(|w| w == b"browser encrypted"),
        "enc-rl-pass.db leaks plaintext"
    );
    util.import_db_unchecked("enc-rl-pass-check.db", &bytes)
        .unwrap();
    util.import_db_unchecked("enc-rl-pass-wrong.db", &bytes)
        .unwrap();
    let v: String = {
        let db = Connection::open("enc-rl-pass-check.db").unwrap();
        db.execute_batch(PASS).unwrap();
        db.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap()
    };
    assert_eq!(v, "browser encrypted", "enc-rl-pass-check.db row mismatch");
    let wrong = Connection::open("enc-rl-pass-wrong.db").unwrap();
    wrong.execute_batch("PRAGMA key = 'wrong'").unwrap();
    assert!(
        wrong
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r
                .get::<_, i64>(0))
            .is_err(),
        "enc-rl-pass-wrong.db must reject wrong key"
    );
}

#[wasm_bindgen_test]
fn cipher_integrity_check_ok() {
    let util = memvfs();
    {
        let db = Db::open("ic-ok.db");
        db.exec(RAW);
        db.exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('a'); INSERT INTO t VALUES ('b');");
    }
    let bytes = util.export_db("ic-ok.db").unwrap();
    util.import_db_unchecked("ic-ok-check.db", &bytes).unwrap();
    let db = Db::open("ic-ok-check.db");
    db.exec(RAW);
    assert_eq!(
        db.one("PRAGMA cipher_integrity_check"),
        Ok(None),
        "ic-ok-check.db integrity check returned unexpected rows"
    );
}

#[wasm_bindgen_test]
fn cipher_integrity_check_corrupted() {
    let util = memvfs();
    {
        let db = Db::open("ic-src.db");
        db.exec(RAW);
        db.exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('a'); INSERT INTO t VALUES ('b');");
    }
    let mut bytes = util.export_db("ic-src.db").unwrap();
    assert!(
        bytes.len() > 4096,
        "ic-src.db export is too short to contain page 2"
    );
    bytes[4096 + 200] ^= 0xFF;
    util.import_db_unchecked("ic-corrupt.db", &bytes).unwrap();
    let db = Db::open("ic-corrupt.db");
    db.exec(RAW);
    assert!(
        matches!(db.one("PRAGMA cipher_integrity_check"), Ok(Some(_))),
        "ic-corrupt.db integrity check should detect the corrupted page"
    );
}

#[wasm_bindgen_test]
fn wal_on_a_keyed_database() {
    let util = memvfs();
    // A plain database proves the journal is observable and would show a leak.
    for (name, key, leaks) in [
        ("journal-plain.db", None, true),
        ("journal-keyed.db", Some(RAW), false),
    ] {
        let db = Db::open(name);
        if let Some(key) = key {
            db.exec(key);
        }
        // rsqlite-vfs 0.2 memvfs has no shared memory, so SQLite keeps the rollback journal.
        assert_eq!(
            db.one("PRAGMA journal_mode=WAL").unwrap().as_deref(),
            Some("delete")
        );
        db.exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('journal-secret')");
        // The journal holds the pages as they were, so the committed row is what it could leak.
        db.exec("BEGIN; UPDATE t SET v = 'replaced'");
        let journal = format!("{name}-journal");
        assert!(
            util.names().unwrap().contains(&journal),
            "{journal} not visible"
        );
        let bytes = util.export_db(&journal).unwrap();
        assert_eq!(
            bytes.windows(14).any(|w| w == b"journal-secret"),
            leaks,
            "{journal}"
        );
        db.exec("ROLLBACK");
    }
}

#[wasm_bindgen_test]
fn memory_security_is_sticky() {
    memvfs();
    let db = Db::open("memsec.db");
    db.exec(RAW);

    // SQLCipher 4.19.0 starts with memory security off.
    assert_eq!(
        db.one("PRAGMA cipher_memory_security").unwrap().as_deref(),
        Some("0"),
        "cipher_memory_security must be 0 by default"
    );
    db.exec("PRAGMA cipher_memory_security = ON");
    assert_eq!(
        db.one("PRAGMA cipher_memory_security").unwrap().as_deref(),
        Some("1"),
        "cipher_memory_security must be 1 after enabling"
    );
    // Once on it stays on, so OFF is ignored.
    db.exec("PRAGMA cipher_memory_security = OFF");
    assert_eq!(
        db.one("PRAGMA cipher_memory_security").unwrap().as_deref(),
        Some("1"),
        "cipher_memory_security must remain 1 after OFF"
    );
}
