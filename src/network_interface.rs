#![expect(dead_code)]
use std::ffi::CString;

#[derive(Eq, Clone)]
pub  struct NetworkInterface {
    pub  name: String,
    pub  index: u32,
    scope: u32,
}

impl NetworkInterface {
    pub  fn new(name: impl Into<String>, scope: u32) -> Self {
        let name = name.into();

        let index = if_nametoindex(&name);

        Self { name, index, scope }
    }

    pub  fn new_with_index(name: impl Into<String>, scope: u32, index: u32) -> Self {
        Self {
            name: name.into(),
            index,
            scope,
        }
    }
}

impl std::fmt::Display for NetworkInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl PartialEq for NetworkInterface {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

fn if_nametoindex(name: &str) -> u32 {
    let name = CString::new(name).expect("Couldn't convert name to CString");

    unsafe { libc::if_nametoindex(name.as_ptr().cast()) };
    1
}
