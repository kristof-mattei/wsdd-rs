#![expect(non_ascii_idents, reason = "Zerocopy")]
#![cfg_attr(
    test,
    expect(dead_code_pub_in_binary, reason = "The test harness is a binary")
)]
pub mod netlink;
