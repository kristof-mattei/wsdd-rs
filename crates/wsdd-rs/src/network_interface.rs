#![expect(unused, reason = "WIP")]
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::io::Error;

use color_eyre::eyre;
use libc::IF_NAMESIZE;

#[derive(Debug)]
pub(crate) struct NetworkInterface {
    name: Box<str>,
    index: u32,
    scope: u8,
}

impl NetworkInterface {
    pub(crate) fn new<I: AsRef<str>>(name: I, scope: u8) -> Result<Self, Error> {
        let name: &str = name.as_ref();

        let index = if_nametoindex(name)?;

        Ok(Self {
            name: name.into(),
            index,
            scope,
        })
    }

    pub(crate) fn new_with_index<'a, I: Into<Cow<'a, str>>>(
        name: I,
        scope: u8,
        index: u32,
    ) -> Self {
        let name = name.into();

        Self {
            name: name.into(),
            index,
            scope,
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn index(&self) -> u32 {
        self.index
    }
}

impl std::fmt::Display for NetworkInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

pub(crate) fn if_nametoindex(name: &str) -> Result<u32, Error> {
    let name = CString::new(name).expect("Couldn't convert name to CString");

    // SAFETY: libc call
    let result = unsafe { libc::if_nametoindex(name.as_ptr().cast()) };

    if result == 0 {
        Err(Error::last_os_error())
    } else {
        Ok(result)
    }
}

pub(crate) fn if_indextoname(index: u32) -> Result<Box<str>, Error> {
    let mut buffer = vec![0_u8; IF_NAMESIZE];

    // SAFETY: libc call
    let result = unsafe { libc::if_indextoname(index, buffer.as_mut_ptr().cast()) };

    if result.is_null() {
        return Err(Error::last_os_error());
    }

    let ifname = CStr::from_bytes_until_nul(&buffer)
        .expect("We used oversized buffer, so not finding a null is impossible")
        .to_str()
        .map_err(|error| Error::new(std::io::ErrorKind::InvalidInput, error))?;

    Ok(String::from(ifname).into_boxed_str())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DevName(Box<str>);

impl TryFrom<Box<str>> for DevName {
    type Error = eyre::Report;

    /// Matches the kernel's [`dev_valid_name`](https://github.com/torvalds/linux/blob/v7.2/net/core/dev.c#L1325-L1340), minus `%`, which [`dev_prep_valid_name`](https://github.com/torvalds/linux/blob/v7.2/net/core/dev.c#L1416-L1431) treats as a template.
    fn try_from(value: Box<str>) -> Result<Self, Self::Error> {
        let valid = !value.is_empty()
            && value.len() < libc::IFNAMSIZ
            && &*value != "."
            && &*value != ".."
            && !value
                .bytes()
                .any(|byte| matches!(byte, b'/' | b':' | b'%' | b'\t'..=b'\r' | b' ' | 0xA0));

        if valid {
            Ok(Self(value))
        } else {
            Err(eyre::Report::msg(format!(
                "`{}` is not a valid interface name",
                value
            )))
        }
    }
}

impl AsRef<str> for DevName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg_attr(test, mockall::automock)]
pub(crate) trait ResolveInterfaceName {
    fn resolve(&self, index: u32) -> Result<Box<str>, Error>;

    fn index_of(&self, name: &str) -> Result<u32, Error>;
}

pub(crate) struct LibcInterfaceNameResolver;

impl ResolveInterfaceName for LibcInterfaceNameResolver {
    fn resolve(&self, index: u32) -> Result<Box<str>, Error> {
        if_indextoname(index)
    }

    fn index_of(&self, name: &str) -> Result<u32, Error> {
        if_nametoindex(name)
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::{assert_eq, assert_matches};

    use crate::network_interface::{DevName, NetworkInterface};

    #[test]
    fn display_only_prints_name() {
        const NAME: &str = "eth0";

        let interface = NetworkInterface::new_with_index(NAME, 0, 1);

        assert_eq!(interface.to_string(), NAME);
    }

    #[test]
    fn dev_name_checks_whitespace_bytes_like_the_kernel() {
        assert_matches!(DevName::try_from(Box::from("eth\t0")), Err(_));
        assert_matches!(DevName::try_from(Box::from("eth 0")), Err(_));
        assert_matches!(DevName::try_from(Box::from("eth\u{a0}0")), Err(_));
        // `à` is `C3 A0`
        assert_matches!(DevName::try_from(Box::from("\u{e0}")), Err(_));
        // U+2003 is `E2 80 83`
        assert_matches!(DevName::try_from(Box::from("eth\u{2003}0")), Ok(_));
    }

    #[test]
    fn dev_name_rejects_templates() {
        assert_matches!(DevName::try_from(Box::from("eth%d")), Err(_));
    }
}
