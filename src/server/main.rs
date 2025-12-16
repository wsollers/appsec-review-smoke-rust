//! Entry point of the smoke server: binds one address, accepts one connection and serves it.
//! This repository is a deliberately vulnerable smoke target for appsec-review; see README.md.
mod cache;
mod request;
mod util;

use std::env;
use std::net::TcpListener;
use std::process;

use util::Frame;

fn main() {
    let mut args = env::args().skip(1);
    let bind = args.next().unwrap_or_else(|| "127.0.0.1:7070".to_string());
    let mut frame = Frame::new();
    util::frame_fill(&mut frame, bind.as_bytes(), bind.len());
    if let Some(name) = args.next() {
        if let Some(text) = util::read_manifest(&name) {
            println!("manifest: {} bytes", text.len());
        }
    }
    let listener = match TcpListener::bind(&bind) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("bind {}: {}", bind, err);
            process::exit(2);
        }
    };
    eprintln!("listening on {} ({} bytes framed)", bind, frame.used);
    let (stream, _peer) = match listener.accept() {
        Ok(accepted) => accepted,
        Err(err) => {
            eprintln!("accept: {}", err);
            process::exit(2);
        }
    };
    let status = request::serve_once(stream);
    process::exit(if status < 500 { 0 } else { 1 });
}
