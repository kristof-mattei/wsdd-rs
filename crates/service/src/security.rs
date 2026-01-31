use std::ffi::CString;
use std::io::Error;
use std::path::Path;

use color_eyre::eyre;
use libc::{setegid, seteuid, setgid, setuid};
use tracing::{Level, event};

#[cfg(any(test, miri))]
const I_DO_NOT_EXIST: &str = "I_DO_NOT_EXIST";

pub fn parse_userspec(user_spec: &str) -> Result<(u32, u32), String> {
    let (user_id, group_id) = user_spec
        .split_once(':')
        .ok_or(String::from("Wrong format (expected `username:groupname`)"))?;

    let uid = { getpwname(user_id) }?;
    let gid = { getgrname(group_id) }?;

    Ok((uid, gid))
}

#[expect(
    clippy::multiple_unsafe_ops_per_block,
    reason = "Deref of unsafe fn that returns a ptr"
)]
fn getpwname(user: &str) -> Result<u32, String> {
    #[cfg(miri)]
    fn getpwname(user: &str) -> Result<u32, String> {
        if user == I_DO_NOT_EXIST {
            Err(format!("User `{}` not found in /etc/passwd", user))
        } else if user == "root" {
            Ok(0)
        } else {
            Ok(1000)
        }
    }

    #[cfg(not(miri))]
    fn getpwname(user: &str) -> Result<u32, String> {
        let u = CString::new(user).unwrap();

        // SAFETY: libc call, needed before calling `getpwnam`
        unsafe {
            *libc::__errno_location() = 0;
        }

        // SAFETY: libc call
        let result = unsafe { libc::getpwnam(u.as_ptr()) };

        // SAFETY: when `Some(_)` the contents are a valid passwd preference
        match unsafe { result.as_ref() } {
            None => {
                // SAFETY: libc call
                if unsafe { *libc::__errno_location() } == 0 {
                    Err(format!("User `{}` not found in /etc/passwd", user))
                } else {
                    Err(format!("{}", Error::last_os_error()))
                }
            },
            Some(passwd) => Ok(passwd.pw_uid),
        }
    }

    getpwname(user)
}

#[expect(
    clippy::multiple_unsafe_ops_per_block,
    reason = "Deref of unsafe fn that returns a ptr"
)]
fn getgrname(group: &str) -> Result<u32, String> {
    #[cfg(miri)]
    fn getgrname(group: &str) -> Result<u32, String> {
        if group == I_DO_NOT_EXIST {
            Err(format!("Group `{}` not found in /etc/group", group))
        } else if group == "root" {
            Ok(0)
        } else {
            Ok(1000)
        }
    }

    #[cfg(not(miri))]
    fn getgrname(group: &str) -> Result<u32, String> {
        let g = CString::new(group).unwrap();

        // SAFETY: libc call, needed before calling `getgrnam`
        unsafe {
            *libc::__errno_location() = 0;
        }

        // SAFETY: libc call
        let result = unsafe { libc::getgrnam(g.as_ptr()) };

        // SAFETY: when `Some(_)` the contents are a valid group reference
        match unsafe { result.as_ref() } {
            None => {
                // SAFETY: libc call
                if unsafe { *libc::__errno_location() } == 0 {
                    Err(format!("Group `{}` not found in /etc/group", group))
                } else {
                    Err(format!("{}", Error::last_os_error()))
                }
            },
            Some(group) => Ok(group.gr_gid),
        }
    }

    getgrname(group)
}

pub fn drop_privileges(uid: u32, gid: u32) -> Result<(), String> {
    // SAFETY: libc calls
    if unsafe { -1 == setgid(gid) } || unsafe { -1 == setegid(gid) } {
        return Err(format!("setgid/setegid failed: {}", Error::last_os_error()));
    }

    event!(Level::DEBUG, "Switched gid to {}", gid);

    // SAFETY: libc calls
    if unsafe { -1 == setuid(uid) } || unsafe { -1 == seteuid(uid) } {
        return Err(format!("setuid/seteuid failed: {}", Error::last_os_error()));
    }

    event!(Level::DEBUG, "Switched uid to {}", uid);

    event!(Level::INFO, "Running as ({}:{})", uid, gid);

    Ok(())
}

/// Chroot into a separate directory to isolate ourself for increased security.
pub fn chroot(root: &Path) -> Result<(), eyre::Report> {
    let path = root
        .to_str()
        .map(|root| CString::new(root).expect("Couldn't convert path to string"))
        .expect("Couldn't convert string to CString");

    // SAFETY: libc call
    let result = unsafe { libc::chroot(path.as_ptr()) };

    if result == -1 {
        return Err(eyre::Report::new(Error::last_os_error()).wrap_err("chroot failed"));
    }

    // SAFETY: libc call
    let result = unsafe { libc::chdir(c"/".as_ptr()) };

    if result == -1 {
        return Err(eyre::Report::new(Error::last_os_error()).wrap_err("chdir failed"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_matches;

    use crate::security::{I_DO_NOT_EXIST, parse_userspec};

    #[test]
    fn parse_userspec_root_root() {
        let result = parse_userspec("root:root");

        assert_matches!(result, Ok((0, 0)));
    }

    #[test]
    fn parse_userspec_invalid_format() {
        let result = parse_userspec("abcabc");

        assert_matches!(result, Err(error) if error == "Wrong format (expected `username:groupname`)");
    }

    #[test]
    fn parse_userspec_non_existing_user() {
        let result = parse_userspec(&format!("{}:root", I_DO_NOT_EXIST));

        assert_matches!(result, Err(error) if error == "User `I_DO_NOT_EXIST` not found in /etc/passwd");
    }

    #[test]
    fn parse_userspec_non_existing_group() {
        let result = parse_userspec(&format!("root:{}", I_DO_NOT_EXIST));

        assert_matches!(result, Err(error) if error == "Group `I_DO_NOT_EXIST` not found in /etc/group");
    }
}
