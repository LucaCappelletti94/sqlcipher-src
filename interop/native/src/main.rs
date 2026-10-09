//! write: creates native-*.db fixture files.  read: opens the files the browser tests wrote.
use rusqlite::Connection;

const RAW: &str =
    "PRAGMA key = \"x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'\"";
const PASS: &str = "PRAGMA key = 'correct horse battery staple'";

fn open(path: &str, key: &str) -> Connection {
    let db = Connection::open(path).unwrap();
    db.execute_batch(key).unwrap();
    db
}

fn open_compat3(path: &str, key: &str) -> Connection {
    let db = Connection::open(path).unwrap();
    db.execute_batch(key).unwrap();
    db.execute_batch("PRAGMA cipher_compatibility = 3").unwrap();
    db
}

fn cipher_version(db: &Connection) -> String {
    db.query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .unwrap()
}

fn assert_integrity(db: &Connection, name: &str) {
    let errors: Vec<String> = db
        .prepare("PRAGMA cipher_integrity_check")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        errors.is_empty(),
        "{name}: cipher_integrity_check failed: {errors:?}"
    );
}

/// Messages `cipher_integrity_check` gives for a file with no page authentication, from SQLCipher 4 and 5.
const NO_AUTHENTICATION: [&str; 2] = [
    "HMAC is not enabled, unable to integrity check",
    "Authentication is not enabled, unable to integrity check",
];

/// Passes when errors is empty or contains only the no-authentication message.
fn assert_setting_integrity(db: &Connection, name: &str) {
    let errors: Vec<String> = db
        .prepare("PRAGMA cipher_integrity_check")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    // cipher_use_hmac = OFF and compat1 always return one fixed message instead of an empty result
    let ok = match errors.as_slice() {
        [] => true,
        [message] => NO_AUTHENTICATION.contains(&message.as_str()),
        _ => false,
    };
    assert!(ok, "{name}: cipher_integrity_check: {errors:?}");
}

struct SettingCase {
    slug: &'static str,
    key: &'static str,
    pragmas: &'static [&'static str],
    /// When true, opening the file without pragmas must fail.
    check_fail: bool,
    /// When true, reads/writes a .salt sidecar file for `cipher_plaintext_header_size` = 32.
    uses_salt: bool,
}

const SETTING_CASES: &[SettingCase] = &[
    SettingCase {
        slug: "page1024",
        key: PASS,
        pragmas: &["PRAGMA cipher_page_size = 1024"],
        check_fail: true,
        uses_salt: false,
    },
    SettingCase {
        slug: "page65536",
        key: PASS,
        pragmas: &["PRAGMA cipher_page_size = 65536"],
        check_fail: true,
        uses_salt: false,
    },
    // kdf_iter and kdf/hmac algorithm settings only affect passphrases, not raw keys
    SettingCase {
        slug: "kdfiter1",
        key: PASS,
        pragmas: &["PRAGMA kdf_iter = 1"],
        check_fail: true,
        uses_salt: false,
    },
    SettingCase {
        slug: "kdfiter1000000",
        key: PASS,
        pragmas: &["PRAGMA kdf_iter = 1000000"],
        check_fail: true,
        uses_salt: false,
    },
    // 5.x authenticates pages with AEAD, where HMAC settings do nothing, so these switch HMAC on as 4.x has it by default.
    SettingCase {
        slug: "hmacsha1",
        key: PASS,
        pragmas: &[
            "PRAGMA cipher_use_hmac = ON",
            "PRAGMA cipher_hmac_algorithm = HMAC_SHA1",
        ],
        check_fail: true,
        uses_salt: false,
    },
    SettingCase {
        slug: "hmacsha256",
        key: PASS,
        pragmas: &[
            "PRAGMA cipher_use_hmac = ON",
            "PRAGMA cipher_hmac_algorithm = HMAC_SHA256",
        ],
        check_fail: true,
        uses_salt: false,
    },
    SettingCase {
        slug: "kdfsha1",
        key: PASS,
        pragmas: &["PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1"],
        check_fail: true,
        uses_salt: false,
    },
    SettingCase {
        slug: "kdfsha256",
        key: PASS,
        pragmas: &["PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA256"],
        check_fail: true,
        uses_salt: false,
    },
    SettingCase {
        slug: "plaintext32",
        key: PASS,
        pragmas: &["PRAGMA cipher_plaintext_header_size = 32"],
        check_fail: true,
        uses_salt: true,
    },
    // 4.x has no cipher_aead and ignores it, while 5.x needs it off before a page can go unauthenticated.
    SettingCase {
        slug: "nohmac",
        key: PASS,
        pragmas: &["PRAGMA cipher_aead = OFF", "PRAGMA cipher_use_hmac = OFF"],
        check_fail: true,
        uses_salt: false,
    },
    SettingCase {
        slug: "compat1",
        key: PASS,
        pragmas: &["PRAGMA cipher_compatibility = 1"],
        check_fail: true,
        uses_salt: false,
    },
    SettingCase {
        slug: "compat2",
        key: PASS,
        pragmas: &["PRAGMA cipher_compatibility = 2"],
        check_fail: true,
        uses_salt: false,
    },
    // compat4 sets the SQLCipher 4 defaults so reading without the pragma uses the same settings
    SettingCase {
        slug: "compat4",
        key: PASS,
        pragmas: &["PRAGMA cipher_compatibility = 4"],
        check_fail: false,
        uses_salt: false,
    },
];

fn write_setting(dir: &str, case: &SettingCase) {
    let name = format!("native-setting-{}.db", case.slug);
    let path = format!("{dir}/{name}");
    let _ = std::fs::remove_file(&path);
    let db = Connection::open(&path).unwrap();
    db.execute_batch(case.key).unwrap();
    for &p in case.pragmas {
        db.execute_batch(p).unwrap();
    }
    let v = cipher_version(&db);
    db.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('written natively');")
        .unwrap();
    if case.uses_salt {
        let salt: String = db
            .query_row("PRAGMA cipher_salt", [], |r| r.get(0))
            .unwrap();
        std::fs::write(
            format!("{dir}/native-setting-{}.salt", case.slug),
            salt.as_bytes(),
        )
        .unwrap();
    }
    drop(db);
    let bytes = std::fs::read(&path).unwrap();
    if case.uses_salt {
        // cipher_plaintext_header_size leaves the SQLite file header visible in plaintext
        assert!(
            bytes.starts_with(b"SQLite format 3\0"),
            "{name}: expected plaintext SQLite header"
        );
    } else {
        assert!(
            !bytes.starts_with(b"SQLite format 3"),
            "{name} is not encrypted"
        );
    }
    assert!(
        !bytes.windows(16).any(|w| w == b"written natively"),
        "{name} leaks plaintext"
    );
    println!("native SQLCipher {v} wrote {name}, {} bytes", bytes.len());
}

fn read_setting(dir: &str, case: &SettingCase) {
    let name = format!("web-setting-{}.db", case.slug);
    let path = format!("{dir}/{name}");
    let salt_pragma = case.uses_salt.then(|| {
        let s = std::fs::read_to_string(format!("{dir}/web-setting-{}.salt", case.slug)).unwrap();
        // Double-quoted identifier delivers x'hex' as zRight to the SQLCipher handler
        format!("PRAGMA cipher_salt = \"x'{s}'\"")
    });
    let db = Connection::open(&path).unwrap();
    db.execute_batch(case.key).unwrap();
    if let Some(sp) = salt_pragma.as_deref() {
        db.execute_batch(sp).unwrap();
    }
    for &p in case.pragmas {
        db.execute_batch(p).unwrap();
    }
    assert_setting_integrity(&db, &name);
    let v: String = db.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
    assert_eq!(v, "written in the browser", "{name}");
    drop(db);
    if case.check_fail {
        let wrong = Connection::open(&path).unwrap();
        wrong.execute_batch(case.key).unwrap();
        assert!(
            wrong
                .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r
                    .get::<_, i64>(0))
                .is_err(),
            "{name}: accessible without required setting"
        );
    }
    // compat4 sets the SQLCipher 4 defaults so reading without the pragma uses the same settings
    println!("native SQLCipher read {name}: {v:?}");
}

fn write_settings(dir: &str) {
    for case in SETTING_CASES {
        write_setting(dir, case);
    }
}

fn read_settings(dir: &str) {
    for case in SETTING_CASES {
        read_setting(dir, case);
    }
}

fn write_one(dir: &str, name: &str, db: Connection) {
    let v = cipher_version(&db);
    db.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('written natively');")
        .unwrap();
    drop(db);
    let bytes = std::fs::read(format!("{dir}/{name}")).unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "{name} is not encrypted"
    );
    assert!(
        !bytes.windows(16).any(|w| w == b"written natively"),
        "{name} leaks plaintext"
    );
    println!(
        "native SQLCipher {v} wrote {name}, {} bytes, encrypted",
        bytes.len()
    );
}

fn wrong_key_rejected(path: &str, name: &str, wrong_key: &str) {
    let wrong = Connection::open(path).unwrap();
    wrong.execute_batch(wrong_key).unwrap();
    assert!(
        wrong
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| {
                r.get::<_, i64>(0)
            })
            .is_err(),
        "{name}: wrong key was accepted"
    );
}

fn read_one(dir: &str, name: &str, db: &Connection, expected: &str, wrong_key: &str) {
    assert_integrity(db, name);
    let v: String = db.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
    assert_eq!(v, expected);
    wrong_key_rejected(&format!("{dir}/{name}"), name, wrong_key);
    println!("native SQLCipher read {name}: {v:?}, wrong key rejected");
}

fn cmd_write(dir: &str) {
    // The Wasm side reads this to open and write these files in the format an older major reads by default.
    let version = cipher_version(&Connection::open_in_memory().unwrap());
    std::fs::write(format!("{dir}/native-version"), &version).unwrap();
    for (name, key) in [
        ("native-raw.db", RAW),
        ("native-pass.db", PASS),
        // wasm tests rekey these
        ("native-rekey-raw.db", RAW),
        ("native-rekey-pass.db", PASS),
    ] {
        let path = format!("{dir}/{name}");
        let _ = std::fs::remove_file(&path);
        write_one(dir, name, open(&path, key));
    }
    // `cipher_compatibility` is ignored until `PRAGMA key` has created the codec.
    let name = "native-compat3-pass.db";
    let path = format!("{dir}/{name}");
    let _ = std::fs::remove_file(&path);
    write_one(dir, name, open_compat3(&path, PASS));
    write_settings(dir);
}

fn cmd_read(dir: &str) {
    for (name, key) in [
        ("web-raw.db", RAW),
        ("web-pass.db", PASS),
        ("rusqlite-raw.db", RAW),
        ("rusqlite-pass.db", PASS),
    ] {
        read_one(
            dir,
            name,
            &open(&format!("{dir}/{name}"), key),
            "written in the browser",
            "PRAGMA key = 'wrong'",
        );
    }
    // rekeyed by wasm tests
    for (name, key, wrong_key) in [
        ("web-rekey-to-pass.db", PASS, RAW),
        ("web-rekey-to-raw.db", RAW, PASS),
        ("rusqlite-rekey-to-pass.db", PASS, RAW),
        ("rusqlite-rekey-to-raw.db", RAW, PASS),
    ] {
        read_one(
            dir,
            name,
            &open(&format!("{dir}/{name}"), key),
            "written natively",
            wrong_key,
        );
    }
    for name in ["web-compat3-pass.db", "rusqlite-compat3-pass.db"] {
        // omitting compat3 makes any key fail on a compat3 file
        read_one(
            dir,
            name,
            &open_compat3(&format!("{dir}/{name}"), PASS),
            "written in the browser",
            "PRAGMA key = 'wrong'",
        );
    }
    read_settings(dir);
}

fn main() {
    let dir = std::env::args().nth(2).unwrap();
    match std::env::args().nth(1).unwrap().as_str() {
        "write" => cmd_write(&dir),
        "read" => cmd_read(&dir),
        _ => unreachable!(),
    }
}
