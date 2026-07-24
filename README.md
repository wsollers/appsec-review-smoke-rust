# appsec-review-smoke-rust

A deliberately vulnerable **smoke target** for [appsec-review](https://github.com/wsollers/appsec-review).
It exists so that a review of a tiny, fully understood Rust program has one correct answer at every
stage. **Do not deploy, run against untrusted input, or reuse any of this code.**

The package builds two binaries: `smoke-server` reads one request line from a TCP connection and
dispatches it; `rust-synthetic` is the code-graph fixture program.

## Build

One Cargo package, no network, no generated code. Registry crates are vendored under `vendor/` and
`.cargo/config.toml` replaces crates.io with that directory:

```sh
cargo build --offline --locked
```

The build is expected to succeed in the appsec-review `rust` build image (rustc and cargo 1.90.0)
as an unprivileged user with networking disabled. The optional features (`legacy-time`,
`normalize`, `threads`, `offsets`) are never enabled; the crates behind them are vendored and
locked but not compiled.

## History

`tools/make-history.sh` rebuilds this repository's commit graph from `tools/history/steps/` with
fixed authors and dates, so the history is reproducible and can be reviewed as code.

## License

MIT; see `LICENSE`. Vendored third-party crates under `vendor/` keep their own licenses.
