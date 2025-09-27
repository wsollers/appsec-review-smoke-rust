//! Small helpers shared by the smoke server. Deliberately vulnerable smoke target; see README.md.
use std::ptr;

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
