use std::ffi::{CString, NulError};
use std::io::Error;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use libc::{setegid, seteuid, setgid, setuid};
use tracing::{Level, event};

#[cfg(any(test, miri))]
const I_DO_NOT_EXIST: &str = "I_DO_NOT_EXIST";

pub(crate) fn parse_userspec(user_spec: &str) -> Result<(u32, u32), String> {
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

#[derive(Debug, thiserror::Error)]
pub(crate) enum DropPrivilegesError {
    #[error("could not switch to {}:{}, setgid/setegid failed: {}", .requested_uid, .requested_gid, .error)]
    Group {
        requested_uid: u32,
        requested_gid: u32,
        error: Error,
    },
    #[error("could not switch to {}:{}, setuid/seteuid failed: {}", .requested_uid, .requested_gid, .error)]
    User {
        requested_uid: u32,
        requested_gid: u32,
        error: Error,
    },
}

pub(crate) fn drop_privileges(uid: u32, gid: u32) -> Result<(), DropPrivilegesError> {
    // SAFETY: libc calls
    if unsafe { -1 == setgid(gid) } || unsafe { -1 == setegid(gid) } {
        return Err(DropPrivilegesError::Group {
            requested_uid: uid,
            requested_gid: gid,
            error: Error::last_os_error(),
        });
    }

    event!(Level::DEBUG, "Switched gid to {}", gid);

    // SAFETY: libc calls
    if unsafe { -1 == setuid(uid) } || unsafe { -1 == seteuid(uid) } {
        return Err(DropPrivilegesError::User {
            requested_uid: uid,
            requested_gid: gid,
            error: Error::last_os_error(),
        });
    }

    event!(Level::DEBUG, "Switched uid to {}", uid);

    event!(Level::INFO, "Running as ({}:{})", uid, gid);

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ChrootError {
    #[error("invalid chroot path: {}", .0)]
    InvalidPath(NulError),
    #[error("could not chroot to {}: {}", .path.display(), .error)]
    Chroot { path: Box<Path>, error: Error },
    #[error("could not chdir to /: {}", .0)]
    Chdir(Error),
}

/// Chroot into a separate directory to isolate ourself for increased security.
pub(crate) fn chroot(root: &Path) -> Result<(), ChrootError> {
    let path = CString::new(root.as_os_str().as_bytes()).map_err(ChrootError::InvalidPath)?;

    // SAFETY: libc call
    let result = unsafe { libc::chroot(path.as_ptr()) };

    if result == -1 {
        let error = Error::last_os_error();

        return Err(ChrootError::Chroot {
            path: root.into(),
            error,
        });
    }

    // SAFETY: libc call
    let result = unsafe { libc::chdir(c"/".as_ptr()) };

    if result == -1 {
        return Err(ChrootError::Chdir(Error::last_os_error()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::io::Error;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;

    use pretty_assertions::{assert_eq, assert_matches};

    use crate::security::{
        ChrootError, DropPrivilegesError, I_DO_NOT_EXIST, chroot, parse_userspec,
    };

    #[test]
    fn drop_privileges_error_names_the_requested_ids_and_the_failed_step() {
        let error = DropPrivilegesError::Group {
            requested_uid: 1000,
            requested_gid: 100,
            error: Error::other("denied"),
        };

        assert_eq!(
            error.to_string(),
            "could not switch to 1000:100, setgid/setegid failed: denied"
        );
    }

    #[test]
    fn chroot_path_with_nul_byte() {
        let result = chroot(Path::new(OsStr::from_bytes(b"/a\0b")));

        assert_matches!(result, Err(ChrootError::InvalidPath(_)));
    }

    #[cfg_attr(not(miri), test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    fn chroot_non_utf8_path_reaches_syscall() {
        let result = chroot(Path::new(OsStr::from_bytes(b"/I_DO_NOT_EXIST_\xff")));

        assert_matches!(result, Err(ChrootError::Chroot { .. }));
    }

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
