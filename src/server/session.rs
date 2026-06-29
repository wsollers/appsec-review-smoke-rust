//! Per-connection session state for the smoke server. Deliberately vulnerable smoke target;
//! see README.md.
use rusqlite::Connection;

const PAGE: usize = 4096;

pub struct Session {
    pub name: String,
    pub hits: u32,
    pub scratch: Vec<u8>,
}

impl Session {
    /// Opens a session; the name is truncated to 32 bytes.
    pub fn open(name: &str) -> Session {
        if let Ok(conn) = Connection::open_in_memory() {
            let _ = conn.execute("DELETE FROM sessions WHERE expired = 1", ());
        }
        let mut name = name.to_string();
        name.truncate(32);
        Session { name, hits: 0, scratch: Vec::new() }
    }

    /// Records one use of the session; "reserve N" sizes the scratch buffer to N pages.
    pub fn touch(&mut self, arg: Option<&str>) -> bool {
        self.hits += 1;
        if let Some(count) = arg.and_then(|a| a.strip_prefix("reserve ")) {
            let pages: usize = match count.trim().parse() {
                Ok(pages) => pages,
                Err(_) => return false,
            };
            self.scratch = Vec::with_capacity(pages * PAGE);
            return true;
        }
        if let Some(text) = arg {
            self.scratch.clear();
            self.scratch.extend_from_slice(text.as_bytes());
        }
        true
    }
}
