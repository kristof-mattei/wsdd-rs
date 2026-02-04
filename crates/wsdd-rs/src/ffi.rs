use std::marker::PhantomData;
use std::ops::Deref;

#[cfg(feature = "systemd")]
use libc::c_int;
#[cfg(feature = "systemd")]
use tracing::{Level, event};

#[cfg(feature = "systemd")]
/// Wrapper around <https://www.man7.org/linux/man-pages/man3/sd_listen_fds.3.html>.
///
/// # Errors
/// See the underlying `sd_listen_fds(3)` systemd function.
pub fn listen_fds(unset_environment: bool) -> Result<Vec<i32>, std::io::Error> {
    #[link(name = "systemd")]
    unsafe extern "C" {
        fn sd_listen_fds(unset_environment: c_int) -> c_int;
    }

    // SAFETY: normal ffi call
    let result = unsafe { sd_listen_fds(unset_environment.into()) };

    if result < 0 {
        Err(std::io::Error::from_raw_os_error(-result))
    } else {
        let v = (3..(3 + result)).collect::<Vec<_>>();

        event!(Level::TRACE, received_fds = ?v, "Received fds from systemd");

        Ok(v)
    }
}

#[cfg(not(feature = "systemd"))]
#[expect(clippy::unnecessary_wraps, reason = "Mirror systemd API")]
pub fn listen_fds(_unset_environment: bool) -> Result<Vec<i32>, std::io::Error> {
    Ok(vec![])
}

#[repr(transparent)]
pub struct SendPtr<'a, T, U>
where
    T: ?Sized,
{
    ptr: *const U,
    _marker: PhantomData<&'a T>,
}

impl<T, U> Deref for SendPtr<'_, T, U>
where
    T: ?Sized,
{
    type Target = *const U;

    fn deref(&self) -> &Self::Target {
        &self.ptr
    }
}

impl<T, U> SendPtr<'_, T, U>
where
    T: ?Sized,
{
    /// Creates a new `SendPtr` from a buffer, starting at the buffer's base address.
    pub fn from_start(anchor: &T) -> Self
    where
        T: AsRef<[u8]>,
    {
        Self {
            ptr: anchor.as_ref().as_ptr().cast::<U>(),
            _marker: PhantomData,
        }
    }

    /// Creates a new `SendPtr` from an existing pointer, anchored to a buffer's lifetime.
    #[expect(unused, reason = "Not used")]
    pub fn from_ptr(_anchor: &T, ptr: *const U) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    /// Mutate the pointer using the given function, preserving the lifetime.
    pub fn mutate<F>(&mut self, f: F)
    where
        F: FnOnce(*const U) -> *const U,
    {
        self.ptr = f(self.ptr);
    }
}
// SAFETY: We are only wrapping a pointer to a buffer that is guaranteed
// to live for 'a. The user must ensure no concurrent writes occur to the underlying buffer.
unsafe impl<T, U> Send for SendPtr<'_, T, U> where T: ?Sized {}

#[cfg(not(miri))]
pub fn getpagesize() -> usize {
    use crate::utils::u32_to_usize;

    unsafe extern "C" {
        fn getpagesize() -> i32;
    }

    // SAFETY: libc call
    let page_size: u32 = unsafe { getpagesize() }.unsigned_abs();

    u32_to_usize(page_size)
}

#[cfg(miri)]
pub fn getpagesize() -> usize {
    const { 1024 * 8 }
}
