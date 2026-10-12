//! SQLCipher on the persistent OPFS `sahpool` VFS, which only exists in a browser dedicated worker.
use rusqlite::{Connection, OptionalExtension};
use sqlite_wasm_rs as ffi;
use sqlite_wasm_rs::vfs::transfer::DbTransfer;
use sqlite_wasm_rs::vfs::VfsFilesManager;
use sqlite_wasm_rs::WasmOsCallback;
use sqlite_wasm_vfs::sahpool::{install, OpfsSAHPoolCfgBuilder, OpfsSAHPoolUtil};
use std::ffi::{CStr, CString};
use std::ptr;
use wasm_bindgen_test::wasm_bindgen_test;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

const PASS: &str = "PRAGMA key = 'correct horse battery staple'";
const RAW: &str =
    "PRAGMA key = \"x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'\"";

#[cfg(sqlcipher_vfs_shim)]
extern "C" {
    /// Wraps the current default VFS in `sqlciphervfs`, replacing whichever VFS it wrapped before.
    fn sqlcipher_register_vfs() -> std::ffi::c_int;
}

/// The VFS a test opens pool's files through, since SQLCipher 5 keys only files opened through `sqlciphervfs`.
const fn through(pool: &'static str) -> &'static str {
    if cfg!(sqlcipher_vfs_shim) {
        "sqlciphervfs"
    } else {
        pool
    }
}

struct Db(*mut ffi::sqlite3);

impl Db {
    fn try_open(vfs: &str, name: &str) -> Result<Self, i32> {
        let vfs_c = CString::new(vfs).unwrap();
        let name_c = CString::new(name).unwrap();
        let mut db = ptr::null_mut();
        let flags = ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE;
        // CString bindings stay live across the FFI call.
        let rc =
            unsafe { ffi::sqlite3_open_v2(name_c.as_ptr(), &raw mut db, flags, vfs_c.as_ptr()) };
        if rc != ffi::SQLITE_OK {
            if !db.is_null() {
                unsafe { ffi::sqlite3_close(db) };
            }
            return Err(rc);
        }
        Ok(Self(db))
    }

    fn open(vfs: &str, name: &str) -> Self {
        Self::try_open(vfs, name).unwrap()
    }

    fn exec(&self, sql: &str) {
        let sql_c = CString::new(sql).unwrap();
        let rc = unsafe {
            ffi::sqlite3_exec(
                self.0,
                sql_c.as_ptr(),
                None,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        // sqlite3_errmsg is guaranteed non-null by the SQLite C API contract.
        assert_eq!(rc, ffi::SQLITE_OK, "{:?}", unsafe {
            CStr::from_ptr(ffi::sqlite3_errmsg(self.0))
        });
    }

    // First column of the first row, None if the query returns no rows, Err on SQL failure.
    fn one(&self, sql: &str) -> Result<Option<String>, String> {
        let sql_c = CString::new(sql).unwrap();
        let mut stmt = ptr::null_mut();
        unsafe {
            // sqlite3_errmsg is guaranteed non-null by the SQLite C API contract.
            if ffi::sqlite3_prepare_v2(self.0, sql_c.as_ptr(), -1, &raw mut stmt, ptr::null_mut())
                != ffi::SQLITE_OK
            {
                return Err(CStr::from_ptr(ffi::sqlite3_errmsg(self.0))
                    .to_string_lossy()
                    .into_owned());
            }
            let result = match ffi::sqlite3_step(stmt) {
                ffi::SQLITE_ROW => {
                    let t = ffi::sqlite3_column_text(stmt, 0);
                    // sqlite3_column_text returns NULL when the column value is SQL NULL.
                    Ok((!t.is_null())
                        .then(|| CStr::from_ptr(t.cast()).to_string_lossy().into_owned()))
                }
                ffi::SQLITE_DONE => Ok(None),
                _ => Err(CStr::from_ptr(ffi::sqlite3_errmsg(self.0))
                    .to_string_lossy()
                    .into_owned()),
            };
            ffi::sqlite3_finalize(stmt);
            result
        }
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        unsafe { ffi::sqlite3_close(self.0) };
    }
}

// 50 rows at ~120 bytes each spans at least two 4096-byte SQLite pages.
fn populate(db: &Db) {
    db.exec("BEGIN");
    for i in 0..50_i32 {
        db.exec(&format!(
            "INSERT INTO t VALUES({i}, 'row-{i:04}-\
             xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')"
        ));
    }
    db.exec("COMMIT");
}

// sahpool holds an Rc, and a single-threaded Wasm worker never sends futures across threads.
#[expect(
    clippy::future_not_send,
    reason = "OpfsSAHPoolUtil uses Rc and is wasm-only"
)]
async fn make_pool(pool: &'static str) -> OpfsSAHPoolUtil {
    let util = install::<WasmOsCallback>(
        &OpfsSAHPoolCfgBuilder::new()
            .vfs_name(pool)
            .directory(&format!("sqlcipher-sahpool-tests/{pool}"))
            .clear_on_init(true)
            .initial_capacity(6)
            .build(),
        cfg!(sqlcipher_vfs_shim),
    )
    .await
    .unwrap();
    // sqlciphervfs wraps the VFS that is the default when it registers, which the install just made the pool.
    #[cfg(sqlcipher_vfs_shim)]
    // SAFETY: the call takes no arguments, and this single-threaded worker has no other code touching the VFS list.
    assert_eq!(unsafe { sqlcipher_register_vfs() }, ffi::SQLITE_OK);
    util
}

#[wasm_bindgen_test]
#[expect(
    clippy::future_not_send,
    reason = "OpfsSAHPoolUtil uses Rc and is wasm-only"
)]
async fn ffi_encrypted_on_sahpool() {
    const POOL: &str = "sqlcipher-sahpool-ffi";
    const VFS: &str = through(POOL);
    let util = make_pool(POOL).await;

    // WAL needs shared memory, which sahpool lacks, so the rollback journal is used.
    {
        let db = Db::open(VFS, "ffi-pass.db");
        db.exec(PASS);
        db.exec("PRAGMA journal_mode=DELETE");
        db.exec("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)");
        populate(&db);
    }

    // Reopen with the correct passphrase and verify row count and integrity.
    {
        let db = Db::open(VFS, "ffi-pass.db");
        db.exec(PASS);
        assert_eq!(
            db.one("SELECT count(*) FROM t").unwrap().as_deref(),
            Some("50"),
            "ffi-pass.db row count mismatch after reopen"
        );
        // cipher_integrity_check returns rows only when corruption is detected.
        assert!(
            db.one("PRAGMA cipher_integrity_check")
                .is_ok_and(|v| v.is_none()),
            "ffi-pass.db integrity check reported corruption"
        );
    }

    // Wrong key must fail on first database access after the PRAGMA key call.
    {
        let db = Db::open(VFS, "ffi-pass.db");
        db.exec("PRAGMA key = 'wrong'");
        assert!(
            db.one("SELECT count(*) FROM sqlite_schema").is_err(),
            "ffi-pass.db accepted a wrong key"
        );
    }

    // Exported bytes must be opaque: no SQLite header, no plaintext row content.
    let bytes = util.export_db("ffi-pass.db").unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "ffi-pass.db export exposes the SQLite header"
    );
    assert!(
        !bytes.windows(6).any(|w| w == b"row-00"),
        "ffi-pass.db export leaks plaintext row data"
    );

    // Raw-key variant: write, reopen, verify opacity.
    {
        let db = Db::open(VFS, "ffi-raw.db");
        db.exec(RAW);
        db.exec("PRAGMA journal_mode=DELETE");
        db.exec("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)");
        populate(&db);
    }
    {
        let db = Db::open(VFS, "ffi-raw.db");
        db.exec(RAW);
        assert_eq!(
            db.one("SELECT count(*) FROM t").unwrap().as_deref(),
            Some("50"),
            "ffi-raw.db row count mismatch after reopen"
        );
    }
    let raw_bytes = util.export_db("ffi-raw.db").unwrap();
    assert!(
        !raw_bytes.starts_with(b"SQLite format 3"),
        "ffi-raw.db export exposes the SQLite header"
    );

    // A plain database on the same pool proves the export shows stored bytes, not decrypted ones.
    {
        let db = Db::open(VFS, "ffi-plain.db");
        db.exec("PRAGMA journal_mode=DELETE");
        db.exec("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)");
        populate(&db);
    }
    let plain_bytes = util.export_db("ffi-plain.db").unwrap();
    assert!(plain_bytes.starts_with(b"SQLite format 3"));
    assert!(plain_bytes.windows(6).any(|w| w == b"row-00"));

    util.clear().unwrap();
    unsafe { util.uninstall().unwrap() };
}

#[wasm_bindgen_test]
#[expect(
    clippy::future_not_send,
    reason = "OpfsSAHPoolUtil uses Rc and is wasm-only"
)]
async fn rusqlite_encrypted_on_sahpool() {
    const POOL: &str = "sqlcipher-sahpool-rl";
    const VFS: &str = through(POOL);
    let util = make_pool(POOL).await;

    // Write via rusqlite with a named VFS and passphrase key.
    {
        let db =
            Connection::open_with_flags_and_vfs("rl-pass.db", rusqlite::OpenFlags::default(), VFS)
                .unwrap();
        db.execute_batch(PASS).unwrap();
        db.execute_batch("PRAGMA journal_mode=DELETE").unwrap();
        db.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
            .unwrap();
        let tx = db.unchecked_transaction().unwrap();
        for i in 0..50_i32 {
            tx.execute(
                "INSERT INTO t VALUES(?1, ?2)",
                rusqlite::params![
                    i,
                    format!(
                        "row-{i:04}-\
                         xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                    )
                ],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }

    // Read back with the correct passphrase and check integrity.
    {
        let db =
            Connection::open_with_flags_and_vfs("rl-pass.db", rusqlite::OpenFlags::default(), VFS)
                .unwrap();
        db.execute_batch(PASS).unwrap();
        let count: i64 = db
            .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 50, "rl-pass.db row count mismatch after reopen");
        // cipher_integrity_check returns rows only when corruption is detected.
        let corruption: Option<String> = db
            .query_row("PRAGMA cipher_integrity_check", [], |r| r.get(0))
            .optional()
            .unwrap();
        assert!(
            corruption.is_none(),
            "rl-pass.db integrity check reported corruption: {corruption:?}"
        );
    }

    // Wrong key must fail on first database access.
    {
        let db =
            Connection::open_with_flags_and_vfs("rl-pass.db", rusqlite::OpenFlags::default(), VFS)
                .unwrap();
        db.execute_batch("PRAGMA key = 'wrong'").unwrap();
        assert!(
            db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r
                .get::<_, i64>(0))
                .is_err(),
            "rl-pass.db accepted a wrong key"
        );
    }

    // Bytes must be opaque.
    let bytes = util.export_db("rl-pass.db").unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "rl-pass.db export exposes the SQLite header"
    );
    assert!(
        !bytes.windows(6).any(|w| w == b"row-00"),
        "rl-pass.db export leaks plaintext row data"
    );

    util.clear().unwrap();
    unsafe { util.uninstall().unwrap() };
}

#[wasm_bindgen_test]
#[expect(
    clippy::future_not_send,
    reason = "OpfsSAHPoolUtil uses Rc and is wasm-only"
)]
async fn rekey_on_sahpool() {
    const POOL: &str = "sqlcipher-sahpool-rekey";
    const VFS: &str = through(POOL);
    let util = make_pool(POOL).await;

    // Write with the original passphrase.
    {
        let db = Db::open(VFS, "rekey.db");
        db.exec(PASS);
        db.exec("PRAGMA journal_mode=DELETE");
        db.exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('before-rekey')");
    }

    // Rekey to a new passphrase on a fresh connection.
    {
        let db = Db::open(VFS, "rekey.db");
        db.exec(PASS);
        db.exec("PRAGMA rekey = 'new passphrase'");
    }

    // New passphrase must open the database and return the row.
    {
        let db = Db::open(VFS, "rekey.db");
        db.exec("PRAGMA key = 'new passphrase'");
        assert_eq!(
            db.one("SELECT v FROM t").unwrap().as_deref(),
            Some("before-rekey"),
            "rekey.db row mismatch after rekey"
        );
    }

    // Original passphrase must now fail.
    {
        let db = Db::open(VFS, "rekey.db");
        db.exec(PASS);
        assert!(
            db.one("SELECT count(*) FROM sqlite_schema").is_err(),
            "rekey.db must reject the original passphrase after rekey"
        );
    }

    util.clear().unwrap();
    unsafe { util.uninstall().unwrap() };
}
