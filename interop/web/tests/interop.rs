//! SQLCipher compiled into sqlite-wasm-rs reads native SQLCipher files and writes files native reads.
use sqlite_wasm_rs as ffi;
use sqlite_wasm_rs::vfs::memvfs::MemVfsUtil;
use sqlite_wasm_rs::vfs::transfer::DbTransfer;
use std::ffi::{CStr, CString};
use wasm_bindgen_test::wasm_bindgen_test;

pub mod common;
use common::{keyed, read_file_sync, write_file_sync, DIR};

const RAW: &str =
    "PRAGMA key = \"x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'\"";
const PASS: &str = "PRAGMA key = 'correct horse battery staple'";
const REKEY_PASS: &str = "PRAGMA rekey = 'correct horse battery staple'";
const REKEY_RAW: &str =
    "PRAGMA rekey = \"x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'\"";

struct Db(*mut ffi::sqlite3);
impl Db {
    fn open(name: &str) -> Self {
        let name = CString::new(name).unwrap();
        let mut db = std::ptr::null_mut();
        let flags = ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE;
        assert_eq!(
            unsafe { ffi::sqlite3_open_v2(name.as_ptr(), &raw mut db, flags, std::ptr::null()) },
            ffi::SQLITE_OK
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
    assert_eq!(unsafe { ffi::sqlite3_initialize() }, ffi::SQLITE_OK);
    unsafe { MemVfsUtil::get() }.unwrap()
}

#[wasm_bindgen_test]
fn sqlcipher_is_compiled_in() {
    memvfs();
    let db = Db::open("probe.db");
    db.exec(RAW);
    let v = db.one("PRAGMA cipher_version").unwrap();
    let p = db.one("PRAGMA cipher_provider").unwrap();
    assert!(
        v.as_deref()
            .is_some_and(|v| v.starts_with(&format!("{} ", interop_web::SQLCIPHER_VERSION))),
        "{v:?}"
    );
    assert_eq!(p.as_deref(), Some("libtomcrypt"));
}

#[wasm_bindgen_test]
fn reads_native_and_writes_for_native() {
    let util = memvfs();
    for (name, key) in [("native-raw.db", RAW), ("native-pass.db", PASS)] {
        util.import_db_unchecked(name, &read_file_sync(&format!("{DIR}/{name}")))
            .unwrap();
        let db = Db::open(name);
        db.exec(&keyed(key));
        assert_eq!(
            db.one("SELECT v FROM t").unwrap().as_deref(),
            Some("written natively")
        );
        let wrong = Db::open(name);
        wrong.exec("PRAGMA key = 'wrong'");
        assert!(
            wrong.one("SELECT count(*) FROM sqlite_schema").is_err(),
            "{name} opened with a wrong key"
        );
    }
    for (name, key) in [("web-raw.db", RAW), ("web-pass.db", PASS)] {
        {
            let db = Db::open(name);
            db.exec(&keyed(key));
            db.exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('written in the browser');");
        }
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
fn rekey_from_raw_to_pass() {
    let util = memvfs();
    util.import_db_unchecked(
        "rekey-raw.db",
        &read_file_sync(&format!("{DIR}/native-rekey-raw.db")),
    )
    .unwrap();
    {
        let db = Db::open("rekey-raw.db");
        db.exec(&keyed(RAW));
        db.exec(REKEY_PASS);
    }
    let bytes = util.export_db("rekey-raw.db").unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "rekey-raw.db is not encrypted after rekey to passphrase"
    );
    write_file_sync(&format!("{DIR}/web-rekey-to-pass.db"), &bytes);
    println!("rekey raw->pass succeeded, {} bytes written", bytes.len());
}

#[wasm_bindgen_test]
fn rekey_from_pass_to_raw() {
    let util = memvfs();
    util.import_db_unchecked(
        "rekey-pass.db",
        &read_file_sync(&format!("{DIR}/native-rekey-pass.db")),
    )
    .unwrap();
    {
        let db = Db::open("rekey-pass.db");
        db.exec(&keyed(PASS));
        db.exec(REKEY_RAW);
    }
    let bytes = util.export_db("rekey-pass.db").unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "rekey-pass.db is not encrypted after rekey to raw key"
    );
    write_file_sync(&format!("{DIR}/web-rekey-to-raw.db"), &bytes);
    println!("rekey pass->raw succeeded, {} bytes written", bytes.len());
}

#[wasm_bindgen_test]
fn compat3_reads_native_and_writes_for_native() {
    let util = memvfs();
    util.import_db_unchecked(
        "compat3-read.db",
        &read_file_sync(&format!("{DIR}/native-compat3-pass.db")),
    )
    .unwrap();
    {
        let db = Db::open("compat3-read.db");
        db.exec(PASS);
        db.exec("PRAGMA cipher_compatibility = 3");
        assert_eq!(
            db.one("SELECT v FROM t").unwrap().as_deref(),
            Some("written natively"),
            "compat3 read from native file returned unexpected value"
        );
    }
    {
        let db = Db::open("compat3-read.db");
        db.exec(PASS);
        assert!(
            db.one("SELECT v FROM t").is_err(),
            "compat3 db decrypted without cipher_compatibility=3, settings had no effect"
        );
    }
    {
        let db = Db::open("compat3-write.db");
        db.exec(PASS);
        db.exec("PRAGMA cipher_compatibility = 3");
        db.exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('written in the browser');");
    }
    let bytes = util.export_db("compat3-write.db").unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "compat3-write.db is not encrypted"
    );
    write_file_sync(&format!("{DIR}/web-compat3-pass.db"), &bytes);
}

#[wasm_bindgen_test]
fn cipher_integrity_check_native_files() {
    let util = memvfs();
    for (name, key) in [("native-raw.db", RAW), ("native-pass.db", PASS)] {
        let vfs_name = format!("ic-{name}");
        util.import_db_unchecked(&vfs_name, &read_file_sync(&format!("{DIR}/{name}")))
            .unwrap();
        let db = Db::open(&vfs_name);
        db.exec(&keyed(key));
        assert_eq!(
            db.one("PRAGMA cipher_integrity_check").unwrap(),
            None,
            "{name} cipher_integrity_check reported an error"
        );
    }
}
