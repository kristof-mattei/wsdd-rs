#![expect(dead_code)]
use std::ffi::{CStr, CString};
use std::io::Error;

use color_eyre::eyre;
use libc::IF_NAMESIZE;

#[derive(Eq, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    scope: u8,
}

impl NetworkInterface {
    pub fn new(name: impl Into<String>, scope: u8) -> Result<Self, eyre::Report> {
        let name = name.into();

        let index = if_nametoindex(&name)?;

        Ok(Self { name, index, scope })
    }

    pub fn new_with_index(name: impl Into<String>, scope: u8, index: u32) -> Self {
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

fn if_nametoindex(name: &str) -> Result<u32, eyre::Report> {
    let name = CString::new(name).expect("Couldn't convert name to CString");

    let result = unsafe { libc::if_nametoindex(name.as_ptr().cast()) };

    if result == 0 {
        Err(eyre::Report::new(Error::last_os_error()).wrap_err("if_nametoindex failed"))
    } else {
        Ok(result)
    }
}

pub fn if_indextoname(index: u32) -> Result<String, eyre::Report> {
    let mut buffer = vec![0u8; IF_NAMESIZE];

    let result = unsafe { libc::if_indextoname(index, buffer.as_mut_ptr().cast()) };

    if result.is_null() {
        return Err(eyre::Report::new(Error::last_os_error()).wrap_err("if_indextoname failed"));
    };

    let ifname = CStr::from_bytes_until_nul(&buffer)
        .expect("We used oversized buffer, so not finding a null is impossible")
        .to_str()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    Ok(String::from(ifname))
}
