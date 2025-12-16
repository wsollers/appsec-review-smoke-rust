//! Per-connection session state for the smoke server. Deliberately vulnerable smoke target;
//! see README.md.

pub struct Session {
    pub name: String,
    pub hits: u32,
    pub scratch: Vec<u8>,
}

impl Session {
    /// Opens a session; the name is truncated to 32 bytes.
    pub fn open(name: &str) -> Session {
        let mut name = name.to_string();
        name.truncate(32);
        Session { name, hits: 0, scratch: Vec::new() }
    }

    /// Records one use of the session and keeps the argument as scratch data.
    pub fn touch(&mut self, arg: Option<&str>) -> bool {
        self.hits += 1;
        if let Some(text) = arg {
            self.scratch.clear();
            self.scratch.extend_from_slice(text.as_bytes());
        }
        true
    }
}
