//! Small helpers shared by the smoke server. Deliberately vulnerable smoke target; see README.md.
use std::fs;
use std::path::Path;
use std::process::Command;
use std::ptr;

const MANIFEST_ROOT: &str = "/etc/smoke";

pub struct Frame {
    pub data: [u8; 64],
    pub used: usize,
}

impl Frame {
    /// A frame in its initial state.
    pub fn new() -> Frame {
        Frame { data: [0; 64], used: 0 }
    }
}

/// Copies up to one frame of payload; longer payloads are refused.
pub fn frame_fill(f: &mut Frame, src: &[u8], n: usize) -> bool {
    if n < f.data.len() && n <= src.len() {
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), f.data.as_mut_ptr(), n) };
        f.used = n;
        return true;
    }
    false
}

/// Reads a manifest named on the command line; the path is canonicalised and must
/// stay under the manifest root.
pub fn read_manifest(name: &str) -> Option<String> {
    let path = fs::canonicalize(Path::new(MANIFEST_ROOT).join(name)).ok()?;
    if !path.starts_with(MANIFEST_ROOT) {
        return None;
    }
    fs::read_to_string(path).ok()
}

/// Flushes pending writes before the server starts serving.
pub fn maintenance_sync() {
    let _ = Command::new("/bin/sync").status();
}
