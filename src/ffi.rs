#[cfg(feature = "systemd")]
use libc::c_int;
#[cfg(feature = "systemd")]
use tracing::{Level, event};

#[cfg(feature = "systemd")]
/// Wrapper around <https://www.man7.org/linux/man-pages/man3/sd_listen_fds.3.html>
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

#[macro_export]
macro_rules! define_typed_size {
    ($name:ident, $target_type:ty, $source:ty) => {
        const $name: $target_type = const {
            let size = core::mem::size_of::<$source>();

            if size > <$target_type>::MAX as usize {
                panic!(concat!(
                    "The size of `",
                    stringify!($source),
                    "` exceeds the capacity of type `",
                    stringify!($target_type),
                    "`"
                ));
            }

            #[expect(
                clippy::cast_possible_truncation,
                reason = "We validate that the size fits in the target size"
            )]
            {
                size as $target_type
            }
        };
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn ui() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/*.rs");
    }
}
