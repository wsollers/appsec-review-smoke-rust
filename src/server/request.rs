//! Request handling for the smoke server. This repository is a deliberately vulnerable
//! smoke target for appsec-review; see README.md.
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};


static REQUESTS: AtomicU32 = AtomicU32::new(0);

/// Handles one request line and returns an HTTP-like status code.
fn handle_request(line: &str, stream: &mut TcpStream) -> u16 {
    let rest = line;
    let rest = rest.trim_end();
    let (verb, arg) = match rest.split_once(' ') {
        Some((verb, arg)) => (verb, Some(arg)),
        None => (rest, None),
    };
    let mut status = 400;
    if verb == "PING" {
        let _ = stream.write_all(b"PONG\n");
        status = 200;
    }
    if status >= 200 && status < 300 {
        REQUESTS.fetch_add(1, Ordering::Relaxed);
    }
    status
}

/// Reads one request line from the connection and handles it.
pub fn serve_once(mut stream: TcpStream) -> u16 {
    let mut line = String::new();
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return 500,
    });
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return 500;
    }
    handle_request(&line, &mut stream)
}
