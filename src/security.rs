use std::ffi::CString;
use std::io::Error;
use std::path::Path;

use color_eyre::eyre;
use libc::{setegid, seteuid, setgid, setuid};
use tracing::{Level, event};

pub fn parse_userspec(user_spec: &str) -> Result<(u32, u32), String> {
    let (user_id, group_id) = user_spec
        .split_once(':')
        .ok_or(String::from("wrong format (expected username:groupname)"))?;

    let uid = unsafe { getpwname(user_id) }?;
    let gid = unsafe { getgrname(group_id) }?;

    Ok((uid, gid))
}

fn getpwname(user: &str) -> Result<u32, String> {
    unsafe { *libc::__errno_location() = 0 };

    let u = CString::new(user).unwrap();
    let result = unsafe { libc::getpwnam(u.as_ptr()) };

    match unsafe { result.as_ref() } {
        None => {
            if unsafe { *libc::__errno_location() } == 0 {
                Err(format!("User '{}' not found in /etc/passwd", user))
            } else {
                Err(format!("{}", Error::last_os_error()))
            }
        },
        Some(passwd) => Ok(passwd.pw_uid),
    }
}

unsafe fn getgrname(group: &str) -> Result<u32, String> {
    unsafe { *libc::__errno_location() = 0 };

    let g = CString::new(group).unwrap();
    let result = unsafe { libc::getgrnam(g.as_ptr()) };

    match unsafe { result.as_ref() } {
        None => {
            if unsafe { *libc::__errno_location() } == 0 {
                Err(format!("Group {} not found in /etc/passwd", group))
            } else {
                Err(format!("{}", Error::last_os_error()))
            }
        },
        Some(group) => Ok(group.gr_gid),
    }
}

pub fn drop_privileges(uid: u32, gid: u32) -> Result<(), String> {
    if unsafe { -1 == setgid(gid) || -1 == setegid(gid) } {
        Err(format!("setgid/setegid failed: {}", Error::last_os_error()))?;
    }

    event!(Level::DEBUG, "Switched gid to {}", gid);

    if unsafe { -1 == setuid(uid) || -1 == seteuid(uid) } {
        Err(format!("setuid/seteuid failed: {}", Error::last_os_error()))?;
    }

    event!(Level::DEBUG, "Switched uid to {}", uid);

    event!(Level::INFO, "Running as ({}:{})", uid, gid);

    Ok(())
}

/// Chroot into a separate directory to isolate ourself for increased security.
pub fn chroot(root: &Path) -> Result<(), eyre::Report> {
    // TODO What's this?
    // # preload for socket.gethostbyaddr()
    // import encodings.idna

    let path = root
        .to_str()
        .map(|root| CString::new(root).expect("Couldn't convert path to string"))
        .expect("Couldn't convert string to CString");

    let result = unsafe { libc::chroot(path.as_ptr().cast()) };

    if result == -1 {
        return Err(eyre::Report::new(Error::last_os_error()).wrap_err("chroot failed"));
    }

    let result = unsafe { libc::chdir(c"/".as_ptr()) };

    if result == -1 {
        return Err(eyre::Report::new(Error::last_os_error()).wrap_err("chdir failed"));
    }

    Ok(())
}
