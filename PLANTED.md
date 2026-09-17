# Planted inventory

This repository is a smoke target for appsec-review. Everything below is deliberate. The
evaluation answer key lives in the separate `appsec-review-smoke-guide` repository; this file
describes the target, it is not the key.

Line numbers refer to the tagged head. The fixture file `src/main.rs` (binary `rust-synthetic`) and
the offline stand-in crates `vendor/reqwest`, `vendor/rusqlite` and `vendor/serde_json` are
byte-identical to `tests/fixtures/graph/codeql_export/rust-synthetic/source/` in appsec-review, so
the line numbers its `expected-facts.json` cites are unchanged.

## True positives, code

| Id | Weakness | Where | Source to sink |
| --- | --- | --- | --- |
| TP-C1 | CWE-89 SQL injection | `src/main.rs` `SqlStore::save` | remote body from `reqwest::blocking::get` in `fetch_body` to `Connection::execute` (fixture case `remote_to_sql`) |
| TP-C2 | CWE-78 command injection | `src/main.rs` `run_tool` | remote body to `Command::new` (fixture case `remote_to_command`) |
| TP-C3 | CWE-918 server-side request forgery | `src/main.rs` `fetch_url` | remote body to `Client::request` (fixture case `remote_to_ssrf`) |
| TP-C4 | CWE-502 deserialization of untrusted data | `src/main.rs` `decode` | remote body to `serde_json::from_str` (fixture case `remote_to_deserialization`) |
| TP-C5 | CWE-22 path traversal | `src/main.rs` `read_file` | `env::var("CONFIG")` to `fs::read_to_string` (fixture case `argv_and_env_sources`) |
| TP-C6 | CWE-117 log injection | `src/server/request.rs` `handle_request`, `LOG` verb | `TcpListener::accept` in `main` and `read_line` in `serve_once` to `log::info!` |
| TP-C7 | CWE-770 uncontrolled allocation size (CWE-190 product) | `src/server/session.rs` `Session::touch`, `SESSION reserve N` | request line to `Vec::with_capacity(pages * PAGE)` |
| TP-C8 | CWE-22 path traversal | `src/server/request.rs` `serve_file`, `GET` verb | request line to `fs::read(TEMPLATE_ROOT.join(name))` |

## True positives, dependencies

Declared in `Cargo.toml` as optional dependencies behind features that are never enabled, pinned in
`Cargo.lock` with their crates.io checksums, and vendored under `vendor/` from the published
`.crate` files (`.cargo/config.toml` replaces crates.io with that directory). `cargo build` resolves
and verifies them but compiles none of them; no source file uses them. Lockfile-reading SBOM tools
see every one at its pinned version.

| Id | Package | Version | Advisory | Fixed in | How it is reached |
| --- | --- | --- | --- | --- | --- |
| TP-D1 | time | 0.1.43 | RUSTSEC-2020-0071 (CVE-2020-26235, GHSA-wcg3-cvx6-7396) | 0.2.23 | direct, feature `legacy-time` |
| TP-D2 | smallvec | 0.6.9 | RUSTSEC-2019-0009 (CVE-2019-15551), RUSTSEC-2019-0012 (CVE-2019-15554), RUSTSEC-2018-0018 (CVE-2018-25023), RUSTSEC-2021-0003 (CVE-2021-25900) | 0.6.10 / 0.6.13 / 0.6.14 | transitive through unicode-normalization 0.1.9, feature `normalize` |
| TP-D3 | crossbeam-utils | 0.8.6 | RUSTSEC-2022-0041 (CVE-2022-23639, GHSA-qc84-gqf4-9926) | 0.8.7 | direct, feature `threads` |

The vendored dependency closure (libc, winapi and its two target crates, cfg-if, lazy_static,
autocfg) and the compiled `log` 0.4.22 crate have clean OSV records.

## Fixed in history

| Id | What | Introduced | Fixed |
| --- | --- | --- | --- |
| FX-C1 | CWE-78 command injection in `run_maintenance` (`sh -c` with the request's tool name) | "Add a TOOL verb that runs maintenance tools" | "Fix command injection in run_maintenance (CWE-78)": the sink was removed |
| FX-C2 | CWE-22 path traversal in `read_asset` | "Add an ASSET verb that serves files from the asset root" | "Fix path traversal in read_asset (CWE-22)": `fs::canonicalize` and a `starts_with` check now dominate `fs::read_to_string` |
| FX-D1 | memoffset 0.5.5 (RUSTSEC-2023-0045, GHSA-wfg4-322g-9vqv) | "Vendor memoffset 0.5.5 behind the offsets feature" | "Upgrade memoffset from 0.5.5 to 0.6.2" |

`SECURITY.md` and `CHANGELOG.md` describe the three fixed items and nothing else.

## False positives

appsec-review mounts no Semgrep or SEI CERT rule for Rust (`rules/semgrep/` targets other
languages; `rules/sei-cert/rules/` has c, cpp and java only), so no mounted rule reports any of
these; they are planted so that a Rust pattern scanner added later has refutable constructs, and the
guide records them as unflagged.

| Id | Where | Flagged by | Refuted by |
| --- | --- | --- | --- |
| FP-1 | `src/server/util.rs` `maintenance_sync`: `Command::new("/bin/sync").status()` | no mounted rule | constant operand: no `dataflow_path` reaches the sink |
| FP-2 | `src/server/util.rs` `frame_fill`: `ptr::copy_nonoverlapping(src, f.data, n)` | no mounted rule | `guard_fact`: `n < f.data.len() && n <= src.len()` dominates the copy and constrains its operand |
| FP-3 | `src/server/util.rs` `read_manifest`: `fs::read_to_string(path)` from `argv` | no mounted rule | `path_sanitizers`: `fs::canonicalize` dominates the sink, with a `starts_with(MANIFEST_ROOT)` guard |
| FP-4 | `src/server/util.rs` `legacy_exec`: `Command::new(command)` | no mounted rule | dead code: no callers, no entry point, so no `dataflow_path` reaches it |
| FP-5 | `src/server/session.rs` `Session::open`: `conn.execute("DELETE FROM sessions WHERE expired = 1", ())` | no mounted rule | constant operand: no `dataflow_path` reaches the sink |

## High-complexity function

`handle_request` in `src/server/request.rs` is the dispatch of the server and the function the
history touches most. It holds TP-C6. Its intended cyclomatic complexity is above 15 by the
appsec-review counter (branches, loops, boolean operators, match arms and `?`); the measured value
is recorded in the guide.

## Code-intelligence cases

`src/main.rs` carries the appsec-review Rust graph-export fixture unchanged: remote, argv and
environment sources, SQL, command, path, request-URL and deserialization sinks, a dominating guard
(`guarded_tool`) and an unguarded sink (`run_tool`), a canonicalize sanitizer (`read_canonical`),
trait-object dispatch (`store.save`), an unresolved closure call (`bump`) and a cross-function flow
summary (`as_owned`, `fetch_url`). The fixture's two known gaps (the remote flow pruned through the
summarised `Response::text`, and the `canonicalize` summary that produces no `path_sanitizers` row)
apply here unchanged. The server adds `TcpListener::accept` as a source, `log::info!` and
`Vec::with_capacity` as sinks, and the fixed state of `read_asset` as a canonicalize sanitizer with
a dominating `starts_with` guard.

## History

Produced by `tools/make-history.sh` from `tools/history/steps/`: 38 commits by three synthetic
authors, dated 2025-05 to 2026-09, including the introduction and fix of each fixed item, a
dependency upgrade, a rename (`src/server/cache.rs` to `src/server/session.rs`), a revert and its
reapply, a hardening review that adds `SECURITY.md`, and a commit body that records an investigated
report found not exploitable (FP-2). Vendoring commits (the stand-in crates, each planted crate with
its dependency closure and checksums, `log`, and the memoffset upgrade) add many files; every other
commit touches at most three.
