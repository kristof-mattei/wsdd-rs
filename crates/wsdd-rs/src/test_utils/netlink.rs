use libc::{NLM_F_DUMP_INTR, NLMSG_DONE, NLMSG_ERROR};
use shared::netlink::{ifinfomsg, nlmsghdr};
use zerocopy::byteorder::native_endian::{I32, U16, U32};
use zerocopy::{FromBytes as _, FromZeros as _, IntoBytes as _};

pub(crate) fn netlink_message(nlmsg_type: u16, payload: &[u8]) -> Vec<u8> {
    let header = nlmsghdr {
        nlmsg_len: U32::new(u32::try_from(size_of::<nlmsghdr>() + payload.len()).unwrap()),
        nlmsg_type: U16::new(nlmsg_type),
        nlmsg_flags: U16::ZERO,
        nlmsg_seq: U32::ZERO,
        nlmsg_pid: U32::ZERO,
    };

    [header.as_bytes(), payload].concat()
}

pub(crate) fn interrupted_message(message: &[u8]) -> Vec<u8> {
    let mut message = message.to_vec();

    let (header, _) = nlmsghdr::mut_from_prefix(&mut message).unwrap();

    header.nlmsg_flags = U16::new(u16::try_from(NLM_F_DUMP_INTR).unwrap());

    message
}

pub(crate) fn done_message() -> Vec<u8> {
    netlink_message(u16::try_from(NLMSG_DONE).unwrap(), 0_i32.as_bytes())
}

pub(crate) fn link_message(nlmsg_type: u16, family: i32, index: i32, flags: u32) -> Vec<u8> {
    let ifi = ifinfomsg {
        ifi_family: u8::try_from(family).unwrap(),
        ifi_pad: 0,
        ifi_type: U16::ZERO,
        ifi_index: I32::new(index),
        ifi_flags: U32::new(flags),
        ifi_change: U32::ZERO,
    };

    netlink_message(nlmsg_type, ifi.as_bytes())
}

pub(crate) fn error_message(error: i32) -> Vec<u8> {
    netlink_message(
        u16::try_from(NLMSG_ERROR).unwrap(),
        &[error.as_bytes(), nlmsghdr::new_zeroed().as_bytes()].concat(),
    )
}
