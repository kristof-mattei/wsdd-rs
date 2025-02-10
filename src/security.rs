use std::{ffi::CString, io::Error};

use libc::{setegid, seteuid, setgid, setuid};
use tracing::{event, Level};

pub  fn parse_userspec(user_spec: &str) -> Result<(u32, u32), String> {
    let (user_id, group_id) = user_spec
        .split_once(':')
        .ok_or(String::from("wrong format (expected username:groupname)"))?;

    let uid = unsafe { getpwname(user_id) }.map_err(|err| format!("{}", err))?;
    let gid = unsafe { getgrname(group_id) }.map_err(|err| format!("{}", err))?;

    Ok((uid, gid))
}

unsafe fn getpwname(user: &str) -> Result<u32, String> {
    *libc::__errno_location() = 0;

    let u = CString::new(user).unwrap();
    let result = libc::getpwnam(u.as_ptr());
    dbg!(*libc::__errno_location());

    if result.is_null() {
        if (*libc::__errno_location()) == 0 {
            Err(format!("User '{}' not found in /etc/passwd", user))
        } else {
            Err(format!("{}", Error::last_os_error()))
        }
    } else {
        Ok((*result).pw_uid)
    }
}

unsafe fn getgrname(group: &str) -> Result<u32, String> {
    *libc::__errno_location() = 0;

    let g = CString::new(group).unwrap();
    let result = libc::getgrnam(g.as_ptr());

    if result.is_null() {
        if (*libc::__errno_location()) == 0 {
            Err(format!("Group {} not found in /etc/passwd", group))
        } else {
            Err(format!("{}", Error::last_os_error()))
        }
    } else {
        Ok((*result).gr_gid)
    }
}

pub  fn drop_privileges(user: &str, uid: u32, gid: u32) -> Result<(), String> {
    unsafe {
        if -1 == setgid(gid) || -1 == setegid(gid) {
            Err(format!(
                "Dropping privileges failed: {}",
                Error::last_os_error()
            ))?;
        }

        event!(Level::DEBUG, "Switched gid to {}", gid);

        if -1 == setuid(uid) || -1 == seteuid(uid) {
            Err(format!(
                "Dropping privileges failed: {}",
                Error::last_os_error()
            ))?;
        }

        event!(Level::DEBUG, "Switched uid to {}", uid);
    }

    event!(Level::INFO, "Running as {}, ({}:{})", user, uid, gid);

    Ok(())
}
