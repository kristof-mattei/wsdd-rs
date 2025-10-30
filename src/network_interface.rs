#![expect(unused, reason = "WIP")]
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::io::Error;

use color_eyre::eyre;
use libc::IF_NAMESIZE;

#[derive(Debug, Eq, Clone)]
pub struct NetworkInterface {
    name: Box<str>,
    index: u32,
    scope: u8,
}

impl NetworkInterface {
    pub fn new<I: AsRef<str>>(name: I, scope: u8) -> Result<Self, std::io::Error> {
        let name: &str = name.as_ref();

        let index = if_nametoindex(name)?;

        Ok(Self {
            name: name.into(),
            index,
            scope,
        })
    }

    pub fn new_with_index<'a, I: Into<Cow<'a, str>>>(name: I, scope: u8, index: u32) -> Self {
        let name = name.into();

        Self {
            name: name.into(),
            index,
            scope,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn index(&self) -> u32 {
        self.index
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

pub fn if_nametoindex(name: &str) -> Result<u32, std::io::Error> {
    let name = CString::new(name).expect("Couldn't convert name to CString");

    // SAFETY: libc call
    let result = unsafe { libc::if_nametoindex(name.as_ptr().cast()) };

    if result == 0 {
        Err(Error::last_os_error())
    } else {
        Ok(result)
    }
}

pub fn if_indextoname(index: u32) -> Result<Box<str>, std::io::Error> {
    let mut buffer = vec![0_u8; IF_NAMESIZE];

    // SAFETY: libc call
    let result = unsafe { libc::if_indextoname(index, buffer.as_mut_ptr().cast()) };

    if result.is_null() {
        return Err(Error::last_os_error());
    }

    let ifname = CStr::from_bytes_until_nul(&buffer)
        .expect("We used oversized buffer, so not finding a null is impossible")
        .to_str()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    Ok(String::from(ifname).into_boxed_str())
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::network_interface::NetworkInterface;

    #[test]
    fn equality() {
        let first = NetworkInterface::new_with_index("eth0", 0, 1);
        let second = NetworkInterface::new_with_index("eth0", 0, 1);

        assert_eq!(first, second);
    }

    #[test]
    fn display_only_prints_name() {
        const NAME: &str = "eth0";

        let interface = NetworkInterface::new_with_index(NAME, 0, 1);

        assert_eq!(interface.to_string(), NAME);
    }
}
