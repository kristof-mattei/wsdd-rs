use libc::c_int;

pub fn listen_fds(unset_environment: bool) -> Result<Vec<i32>, std::io::Error> {
    #[link(name = "systemd")]
    unsafe extern "C" {
        fn sd_listen_fds(unset_environment: c_int) -> c_int;
    }

    // SAFETY: normal ffi call
    let result = unsafe { sd_listen_fds(unset_environment.into()) };

    #[expect(clippy::single_match_else, reason = "Clarity")]
    match result {
        ..0 => Err(std::io::Error::from_raw_os_error(result)),
        0.. => {
            let v = (3..(3 + result)).collect::<Vec<_>>();

            Ok(v)
        },
    }
}
