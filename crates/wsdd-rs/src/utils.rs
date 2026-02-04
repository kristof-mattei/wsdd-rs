use tokio::task::JoinHandle;

use crate::shutdown::Shutdown;

pub mod env;
pub mod task;

pub async fn flatten_shutdown_handle(handle: JoinHandle<Shutdown>) -> Shutdown {
    match handle.await {
        Ok(shutdown) => shutdown,
        Err(join_error) => Shutdown::UnexpectedError(join_error.into()),
    }
}

/// Utility struct to format the elements using the Display trait instead of the Debug trait.
#[repr(transparent)]
pub struct SliceDisplay<'s, T>(pub &'s [T]);

impl<T: std::fmt::Display> std::fmt::Display for SliceDisplay<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut iter = self.0.iter();

        let Some(first) = iter.next() else {
            return Ok(());
        };

        write!(f, "[{}", first)?;

        for next in iter {
            write!(f, ", {}", next)?;
        }

        write!(f, "]")?;

        Ok(())
    }
}

#[repr(transparent)]
pub struct SocketAddrDisplay<'s, T: AsRef<tokio::net::UdpSocket>>(pub &'s T);

impl<T: AsRef<tokio::net::UdpSocket>> std::fmt::Display for SocketAddrDisplay<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.as_ref().local_addr() {
            Ok(addr) => write!(f, "{}", addr),
            Err(error) => write!(f, "Failed to get local socket address: {:?}", error),
        }
    }
}

// because `From::from` cannot be called in `const` yet
pub const fn u16_to_usize(from: u16) -> usize {
    const _: () = assert!(
        usize::BITS >= u16::BITS,
        "We only support 32-bit/64-bit platforms so this should not fail"
    );

    from as usize
}

// because `From::from` cannot be called in `const` yet
// having raw `as usize` is dangerous, as copy-pasting might
// do it on a `value_u64 as usize` on a 32-bit platform which truncates
pub const fn u32_to_usize(from: u32) -> usize {
    const _: () = assert!(
        usize::BITS >= 32,
        "rtnetlink doesn't support 16-bit, so we don't either"
    );

    from as usize
}
