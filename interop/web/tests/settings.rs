//! Every cipher setting crosses both ways, native writing for Wasm and Wasm writing for native.
use sqlite_wasm_rs as ffi;
use sqlite_wasm_rs::vfs::memvfs::MemVfsUtil;
use sqlite_wasm_rs::vfs::transfer::DbTransfer;
use std::ffi::{CStr, CString};
use wasm_bindgen_test::wasm_bindgen_test;

pub mod common;
use common::{keyed, read_file_sync, write_file_sync, DIR};

// KDF settings only affect passphrase keys, so every case uses one.
const PASS: &str = "PRAGMA key = 'correct horse battery staple'";

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

/// First column of the first row, panicking on any error, missing row or `NULL`.
fn read_first(db: &Db, sql: &str) -> String {
    let sql_c = CString::new(sql).unwrap();
    let mut stmt = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            ffi::sqlite3_prepare_v2(
                db.0,
                sql_c.as_ptr(),
                -1,
                &raw mut stmt,
                std::ptr::null_mut(),
            )
        },
        ffi::SQLITE_OK,
        "prepare failed: {sql:?}"
    );
    assert_eq!(
        unsafe { ffi::sqlite3_step(stmt) },
        ffi::SQLITE_ROW,
        "no row from: {sql:?}"
    );
    // The text dies with the statement, so it is copied before finalizing.
    let val = unsafe {
        let t = ffi::sqlite3_column_text(stmt, 0);
        assert!(!t.is_null(), "NULL column 0 from: {sql:?}");
        CStr::from_ptr(t.cast()).to_string_lossy().into_owned()
    };
    unsafe { ffi::sqlite3_finalize(stmt) };
    val
}

/// Whether the SQL prepares and steps without error.
fn can_execute(db: &Db, sql: &str) -> bool {
    let sql_c = CString::new(sql).unwrap();
    let mut stmt = std::ptr::null_mut();
    let ok = unsafe {
        ffi::sqlite3_prepare_v2(
            db.0,
            sql_c.as_ptr(),
            -1,
            &raw mut stmt,
            std::ptr::null_mut(),
        )
    } == ffi::SQLITE_OK;
    if !ok {
        unsafe { ffi::sqlite3_finalize(stmt) };
        return false;
    }
    let step = unsafe { ffi::sqlite3_step(stmt) };
    unsafe { ffi::sqlite3_finalize(stmt) };
    step == ffi::SQLITE_ROW || step == ffi::SQLITE_DONE
}

/// First row of `cipher_integrity_check`, or None when no rows are returned.
fn integrity_check_row(db: &Db) -> Option<String> {
    let sql_c = CString::new("PRAGMA cipher_integrity_check").unwrap();
    let mut stmt = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            ffi::sqlite3_prepare_v2(
                db.0,
                sql_c.as_ptr(),
                -1,
                &raw mut stmt,
                std::ptr::null_mut(),
            )
        },
        ffi::SQLITE_OK
    );
    let row = unsafe {
        if ffi::sqlite3_step(stmt) == ffi::SQLITE_ROW {
            let t = ffi::sqlite3_column_text(stmt, 0);
            // The text dies with the statement, so it is copied before finalizing.
            if t.is_null() {
                Some(String::new())
            } else {
                Some(CStr::from_ptr(t.cast()).to_string_lossy().into_owned())
            }
        } else {
            None
        }
    };
    unsafe { ffi::sqlite3_finalize(stmt) };
    row
}

/// Messages `cipher_integrity_check` gives for a file with no page authentication, from SQLCipher 4 and 5.
const NO_AUTHENTICATION: [&str; 2] = [
    "HMAC is not enabled, unable to integrity check",
    "Authentication is not enabled, unable to integrity check",
];

/// Asserts `cipher_integrity_check` returns no rows or says the file has no page authentication.
fn assert_integrity(db: &Db, label: &str) {
    let row = integrity_check_row(db);
    // cipher_use_hmac = OFF and compat1 always produce this message instead of an empty result
    assert!(
        row.as_deref()
            .is_none_or(|row| NO_AUTHENTICATION.contains(&row)),
        "{label}: unexpected cipher_integrity_check row: {row:?}"
    );
}

struct Case {
    slug: &'static str,
    pragmas: &'static [&'static str],
    /// When true, opening the file without pragmas must fail.
    check_fail_without: bool,
    /// When true, reads/writes a .salt sidecar file for `cipher_plaintext_header_size` = 32.
    uses_salt: bool,
}

const CASES_PAGE: &[Case] = &[
    Case {
        slug: "page1024",
        pragmas: &["PRAGMA cipher_page_size = 1024"],
        check_fail_without: true,
        uses_salt: false,
    },
    Case {
        slug: "page65536",
        pragmas: &["PRAGMA cipher_page_size = 65536"],
        check_fail_without: true,
        uses_salt: false,
    },
];

const CASES_KDFITER: &[Case] = &[
    Case {
        slug: "kdfiter1",
        pragmas: &["PRAGMA kdf_iter = 1"],
        check_fail_without: true,
        uses_salt: false,
    },
    Case {
        slug: "kdfiter1000000",
        pragmas: &["PRAGMA kdf_iter = 1000000"],
        check_fail_without: true,
        uses_salt: false,
    },
];

// 5.x authenticates pages with AEAD, where HMAC settings do nothing, so these switch HMAC on as 4.x has it by default.
const CASES_HMAC_ALG: &[Case] = &[
    Case {
        slug: "hmacsha1",
        pragmas: &[
            "PRAGMA cipher_use_hmac = ON",
            "PRAGMA cipher_hmac_algorithm = HMAC_SHA1",
        ],
        check_fail_without: true,
        uses_salt: false,
    },
    Case {
        slug: "hmacsha256",
        pragmas: &[
            "PRAGMA cipher_use_hmac = ON",
            "PRAGMA cipher_hmac_algorithm = HMAC_SHA256",
        ],
        check_fail_without: true,
        uses_salt: false,
    },
];

const CASES_KDF_ALG: &[Case] = &[
    Case {
        slug: "kdfsha1",
        pragmas: &["PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1"],
        check_fail_without: true,
        uses_salt: false,
    },
    Case {
        slug: "kdfsha256",
        pragmas: &["PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA256"],
        check_fail_without: true,
        uses_salt: false,
    },
];

const CASE_PLAINTEXT: Case = Case {
    slug: "plaintext32",
    pragmas: &["PRAGMA cipher_plaintext_header_size = 32"],
    check_fail_without: true,
    uses_salt: true,
};

// 4.x has no cipher_aead and ignores it, while 5.x needs it off before a page can go unauthenticated.
const CASE_NOHMAC: Case = Case {
    slug: "nohmac",
    pragmas: &["PRAGMA cipher_aead = OFF", "PRAGMA cipher_use_hmac = OFF"],
    check_fail_without: true,
    uses_salt: false,
};

const CASES_COMPAT: &[Case] = &[
    Case {
        slug: "compat1",
        pragmas: &["PRAGMA cipher_compatibility = 1"],
        check_fail_without: true,
        uses_salt: false,
    },
    Case {
        slug: "compat2",
        pragmas: &["PRAGMA cipher_compatibility = 2"],
        check_fail_without: true,
        uses_salt: false,
    },
    // compat4 sets the SQLCipher 4 defaults so reading without the pragma uses the same settings
    Case {
        slug: "compat4",
        pragmas: &["PRAGMA cipher_compatibility = 4"],
        check_fail_without: false,
        uses_salt: false,
    },
];

fn run_setting(util: &MemVfsUtil, case: &Case) {
    let slug = case.slug;

    // --- Read native-written file ---
    let native_vfs = format!("sn-{slug}");
    util.import_db_unchecked(
        &native_vfs,
        &read_file_sync(&format!("{DIR}/native-setting-{slug}.db")),
    )
    .unwrap();
    let native_salt = case.uses_salt.then(|| {
        String::from_utf8(read_file_sync(&format!("{DIR}/native-setting-{slug}.salt"))).unwrap()
    });
    {
        let db = Db::open(&native_vfs);
        db.exec(&keyed(PASS));
        if let Some(salt) = &native_salt {
            // Double-quoted identifier delivers x'hex' as zRight to the SQLCipher handler
            db.exec(&format!("PRAGMA cipher_salt = \"x'{salt}'\""));
        }
        for &p in case.pragmas {
            db.exec(p);
        }
        assert_integrity(&db, &native_vfs);
        assert_eq!(
            read_first(&db, "SELECT v FROM t"),
            "written natively",
            "{native_vfs}: native data read failed"
        );
    }
    if case.check_fail_without {
        let wrong = Db::open(&native_vfs);
        wrong.exec(&keyed(PASS));
        assert!(
            !can_execute(&wrong, "SELECT count(*) FROM sqlite_schema"),
            "{native_vfs}: must be inaccessible without the setting"
        );
    }
    // compat4 sets the SQLCipher 4 defaults, so reading without the pragma uses the same settings

    // --- Write Wasm file with the setting ---
    let web_vfs = format!("sw-{slug}");
    let web_salt = {
        let db = Db::open(&web_vfs);
        db.exec(&keyed(PASS));
        for &p in case.pragmas {
            db.exec(p);
        }
        db.exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('written in the browser');");
        // A plaintext header hides the salt, so it is read before the connection closes.
        case.uses_salt
            .then(|| read_first(&db, "PRAGMA cipher_salt"))
        // db closes here, flushing writes to memvfs
    };
    let bytes = util.export_db(&web_vfs).unwrap();
    if case.uses_salt {
        // cipher_plaintext_header_size leaves the first 16 bytes of the SQLite file header visible
        assert!(
            bytes.starts_with(b"SQLite format 3\0"),
            "{web_vfs}: expected plaintext SQLite format 3 header in first 16 bytes"
        );
        write_file_sync(
            &format!("{DIR}/web-setting-{slug}.salt"),
            web_salt.as_deref().unwrap().as_bytes(),
        );
    } else {
        assert!(
            !bytes.starts_with(b"SQLite format 3"),
            "{web_vfs}: file is not encrypted"
        );
        assert!(
            !bytes.windows(22).any(|w| w == b"written in the browser"),
            "{web_vfs}: file leaks plaintext"
        );
    }
    write_file_sync(&format!("{DIR}/web-setting-{slug}.db"), &bytes);
    {
        let db = Db::open(&web_vfs);
        db.exec(&keyed(PASS));
        if let Some(salt) = &web_salt {
            db.exec(&format!("PRAGMA cipher_salt = \"x'{salt}'\""));
        }
        for &p in case.pragmas {
            db.exec(p);
        }
        assert_integrity(&db, &web_vfs);
    }
}

#[wasm_bindgen_test]
fn settings_page_size() {
    let util = memvfs();
    for case in CASES_PAGE {
        run_setting(&util, case);
    }
}

#[wasm_bindgen_test]
fn settings_kdf_iter() {
    let util = memvfs();
    for case in CASES_KDFITER {
        run_setting(&util, case);
    }
}

#[wasm_bindgen_test]
fn settings_hmac_algorithm() {
    let util = memvfs();
    for case in CASES_HMAC_ALG {
        run_setting(&util, case);
    }
}

#[wasm_bindgen_test]
fn settings_kdf_algorithm() {
    let util = memvfs();
    for case in CASES_KDF_ALG {
        run_setting(&util, case);
    }
}

#[wasm_bindgen_test]
fn settings_plaintext_header() {
    run_setting(&memvfs(), &CASE_PLAINTEXT);
}

#[wasm_bindgen_test]
fn settings_use_hmac() {
    run_setting(&memvfs(), &CASE_NOHMAC);
}

#[wasm_bindgen_test]
fn settings_compat() {
    let util = memvfs();
    for case in CASES_COMPAT {
        run_setting(&util, case);
    }
}
