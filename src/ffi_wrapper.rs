use std::io::Error;
use std::mem::{size_of_val, MaybeUninit};
use std::os::unix::prelude::AsRawFd;
use std::ptr::{addr_of, null_mut};

use color_eyre::eyre;
use libc::{c_int, c_void, setsockopt, sigaction, sigset_t, socklen_t, SOL_SOCKET, SO_RCVBUF};
use tokio::net::TcpStream;
use tracing::Level;

use crate::wrap_and_report;

#[expect(unused)]
pub  fn set_receive_buffer_size(
    tcp_stream: &TcpStream,
    size_in_bytes: usize,
) -> Result<(), Error> {
    // Set the smallest possible recieve buffer. This reduces local
    // resource usage and slows down the remote end.
    let value: i32 = i32::try_from(size_in_bytes).expect("Byte buffer didn't fit in an i32");

    #[allow(clippy::cast_possible_truncation)]
    let r: c_int = unsafe {
        setsockopt(
            tcp_stream.as_raw_fd(),
            SOL_SOCKET,
            SO_RCVBUF,
            addr_of!(value).cast::<c_void>(),
            size_of_val(&value) as socklen_t,
        )
    };

    if r == -1 {
        return Err(Error::last_os_error());
    }

    Ok(())
}

#[allow(unused)]
pub  fn set_up_handler(
    signum: c_int,
    handler: extern "C" fn(_: c_int),
) -> Result<(), eyre::Report> {
    let sa = sigaction {
        sa_sigaction: handler as usize,
        sa_flags: 0,
        sa_mask: unsafe { MaybeUninit::<sigset_t>::zeroed().assume_init() },
        #[cfg(not(target_os = "macos"))]
        sa_restorer: None,
    };

    if unsafe { sigaction(signum, &sa, null_mut()) } == -1 {
        return Err(wrap_and_report!(
            Level::ERROR,
            Error::last_os_error(),
            "Failure to install signal handler"
        ));
    }

    Ok(())
}
