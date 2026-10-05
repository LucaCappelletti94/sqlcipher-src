# sqlcipher-src

[![CI](https://github.com/LucaCappelletti94/sqlcipher-src/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/sqlcipher-src/actions/workflows/ci.yml)
[![CodeQL](https://github.com/LucaCappelletti94/sqlcipher-src/actions/workflows/codeql.yml/badge.svg)](https://github.com/LucaCappelletti94/sqlcipher-src/actions/workflows/codeql.yml)
[![ClusterFuzzLite](https://github.com/LucaCappelletti94/sqlcipher-src/actions/workflows/cflite_build.yml/badge.svg)](https://github.com/LucaCappelletti94/sqlcipher-src/actions/workflows/cflite_build.yml)
[![codecov](https://codecov.io/gh/LucaCappelletti94/sqlcipher-src/graph/badge.svg?token=iyDt4aR7wE)](https://codecov.io/gh/LucaCappelletti94/sqlcipher-src)
[![Quality gate](https://sonarcloud.io/api/project_badges/measure?project=LucaCappelletti94_sqlcipher-wasm-src&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=LucaCappelletti94_sqlcipher-wasm-src)
[![SQLCipher release](https://github.com/LucaCappelletti94/sqlcipher-src/actions/workflows/sqlcipher-release.yml/badge.svg)](https://github.com/LucaCappelletti94/sqlcipher-src/actions/workflows/sqlcipher-release.yml)
[![SQLCipher branches](https://github.com/LucaCappelletti94/sqlcipher-src/actions/workflows/sqlcipher-branches.yml/badge.svg)](https://github.com/LucaCappelletti94/sqlcipher-src/actions/workflows/sqlcipher-branches.yml)
[![crates.io](https://img.shields.io/crates/v/sqlcipher-src.svg)](https://crates.io/crates/sqlcipher-src)
[![docs.rs](https://docs.rs/sqlcipher-src/badge.svg)](https://docs.rs/sqlcipher-src)
[![license](https://img.shields.io/badge/license-MIT%20AND%20BSD--3--Clause%20AND%20blessing%20AND%20WTFPL-blue.svg)](https://github.com/LucaCappelletti94/sqlcipher-src/blob/main/Cargo.toml)

The [SQLCipher](https://github.com/sqlcipher/sqlcipher) amalgamation as C source for `-sys` crates, on native targets and on `wasm32-unknown-unknown` through [`sqlite-wasm-rs`](https://github.com/Spxg/sqlite-wasm-rs), where it adds the [libtomcrypt](https://github.com/libtom/libtomcrypt) crypto provider.

Native builds compile `SOURCE_FILE` with their own crypto provider and flags:

```rust
let dir = sqlcipher_src::source_dir();
assert!(dir.join(sqlcipher_src::SOURCE_FILE).is_file());
assert!(dir.join(sqlcipher_src::HEADER_FILE).is_file());
```

`sqlite-wasm-rs` 0.6 compiles `WASM_SOURCE_FILE` instead of plain SQLite when `SQLITE_WASM_RS_SOURCE_DIR` points at the same directory, set in the environment or in `[env]` of `.cargo/config.toml`:

```sh
export SQLITE_WASM_RS_SOURCE_DIR="$(cargo metadata --format-version 1 \
  | jq -r '.packages[] | select(.name == "sqlcipher-src") | .manifest_path' \
  | xargs dirname)/sqlcipher"
cargo build --target wasm32-unknown-unknown
```

Shared-memory builds (`+atomics`) also need `-mbulk-memory` in `CFLAGS_wasm32_unknown_unknown`.

The sources are generated from signed SQLCipher and libtomcrypt releases by `upgrade.sh`. CI runs `rusqlite`'s SQLCipher tests on them natively, and checks that files written natively and in Node, Chrome and Firefox open on both sides. `ClusterFuzzLite` fuzzes the Wasm build under `AddressSanitizer`, `UndefinedBehaviorSanitizer` and `MemorySanitizer`, through a script interpreter that drives every codec operation (key, rekey, pragma, attach, backup, cache-race and injected I/O/allocation faults) under nine oracles (tampered-page authentication, plaintext leakage, IV/salt uniqueness, logical-content preservation, and more), plus two file-format targets exercising an attacker handing over database bytes directly, one without the key and one with it. It checks that the libtomcrypt and OpenSSL builds read every fuzzed file the same way, and that SQLCipher and plain SQLite agree on logical content for the same input.

The same checks run on SQLCipher's newest signed pre-release, and daily on the heads of its `prerelease` and `beta` branches. Nothing from those lines ships.

The wrapper is MIT, SQLCipher is BSD-3-Clause, SQLite is public domain, and libtomcrypt is public domain or WTFPL.
