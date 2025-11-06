//! Request handling for the smoke server. This repository is a deliberately vulnerable
//! smoke target for appsec-review; see README.md.
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

const ASSET_ROOT: &str = "/var/lib/smoke/assets";
const TEMPLATE_ROOT: &str = "/var/lib/smoke/templates";

static REQUESTS: AtomicU32 = AtomicU32::new(0);

/// Serves a template named by the request; returns its bytes or None.
fn serve_file(name: &str) -> Option<Vec<u8>> {
    fs::read(Path::new(TEMPLATE_ROOT).join(name)).ok()
}

/// Reads an asset named by the request; returns its text or None.
fn read_asset(name: &str) -> Option<String> {
    fs::read_to_string(Path::new(ASSET_ROOT).join(name)).ok()
}

/// Runs a maintenance tool named by the request.
fn run_maintenance(name: &str) -> bool {
    let command = format!("/usr/libexec/smoke/{} --status", name);
    Command::new("sh")
        .arg("-c")
        .arg(command)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

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
    } else if let ("GET", Some(name)) = (verb, arg) {
        status = match serve_file(name) {
            Some(body) => {
                let _ = stream.write_all(&body);
                200
            }
            None => 404,
        };
    } else if let ("ASSET", Some(name)) = (verb, arg) {
        status = match read_asset(name) {
            Some(text) => {
                let _ = stream.write_all(text.as_bytes());
                200
            }
            None => 404,
        };
    } else if let ("TOOL", Some(name)) = (verb, arg) {
        status = if run_maintenance(name) { 200 } else { 500 };
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
