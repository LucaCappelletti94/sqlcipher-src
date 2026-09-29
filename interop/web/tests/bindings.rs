//! The generated bindings key, rekey and reject through `sqlite3_key` and `sqlite3_rekey`, with no `PRAGMA`.
use interop_web::sqlcipher as ffi;
use sqlite_wasm_rs::vfs::memvfs::MemVfsUtil;
use sqlite_wasm_rs::vfs::transfer::DbTransfer;
use std::ffi::CString;
use wasm_bindgen_test::wasm_bindgen_test;

const OLD: &[u8] = b"correct horse battery staple";
const NEW: &[u8] = b"a different passphrase";

struct Db(*mut ffi::sqlite3);

impl Db {
    fn open(name: &str) -> Self {
        let name = CString::new(name).unwrap();
        let mut db = std::ptr::null_mut();
        let flags = ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE;
        let rc =
            unsafe { ffi::sqlite3_open_v2(name.as_ptr(), &raw mut db, flags, std::ptr::null()) };
        assert_eq!(rc, ffi::SQLITE_OK);
        Self(db)
    }

    fn key(&self, key: &[u8]) {
        let rc = unsafe { ffi::sqlite3_key(self.0, key.as_ptr().cast(), c_len(key)) };
        assert_eq!(rc, ffi::SQLITE_OK);
    }

    fn rekey(&self, key: &[u8]) {
        let rc = unsafe { ffi::sqlite3_rekey(self.0, key.as_ptr().cast(), c_len(key)) };
        assert_eq!(rc, ffi::SQLITE_OK);
    }

    fn exec(&self, sql: &str) -> i32 {
        let sql = CString::new(sql).unwrap();
        unsafe {
            ffi::sqlite3_exec(
                self.0,
                sql.as_ptr(),
                None,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        unsafe { ffi::sqlite3_close(self.0) };
    }
}

fn c_len(key: &[u8]) -> i32 {
    i32::try_from(key.len()).unwrap()
}

#[wasm_bindgen_test]
fn bindings_key_and_rekey_the_sources() {
    assert_eq!(unsafe { ffi::sqlite3_initialize() }, ffi::SQLITE_OK);
    let util = unsafe { MemVfsUtil::get() }.unwrap();
    {
        let db = Db::open("bindings.db");
        db.key(OLD);
        let rc = db.exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('bindings-secret')");
        assert_eq!(rc, ffi::SQLITE_OK);
    }
    let bytes = util.export_db("bindings.db").unwrap();
    assert!(!bytes.is_empty());
    assert!(!bytes.starts_with(b"SQLite format 3"));
    assert!(!bytes.windows(15).any(|w| w == b"bindings-secret"));
    {
        let db = Db::open("bindings.db");
        db.key(OLD);
        assert_eq!(db.exec("SELECT v FROM t"), ffi::SQLITE_OK);
        db.rekey(NEW);
    }
    let old = Db::open("bindings.db");
    old.key(OLD);
    assert_eq!(
        old.exec("SELECT count(*) FROM sqlite_schema"),
        ffi::SQLITE_NOTADB
    );
    let new = Db::open("bindings.db");
    new.key(NEW);
    assert_eq!(new.exec("SELECT v FROM t"), ffi::SQLITE_OK);
}
