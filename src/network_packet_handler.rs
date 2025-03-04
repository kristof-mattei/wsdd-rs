use crate::udp_address::UdpAddress;

#[expect(unused)]
pub trait NetworkPacketHandler {
    fn handle_packet(&self, msg: &str, udp_src_address: &UdpAddress);
}
