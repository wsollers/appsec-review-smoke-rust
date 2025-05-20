# appsec-review-smoke-rust

A deliberately vulnerable **smoke target** for [appsec-review](https://github.com/wsollers/appsec-review).
It exists so that a review of a tiny, fully understood Rust program has one correct answer at every
stage. **Do not deploy, run against untrusted input, or reuse any of this code.**

The package builds two binaries: `smoke-server` reads one request line from a TCP connection and
dispatches it; `rust-synthetic` is the code-graph fixture program.

## License

MIT; see `LICENSE`. Vendored third-party crates under `vendor/` keep their own licenses.
