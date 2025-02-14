use crate::udp_address::UdpAddress;

pub trait NetworkPacketHandler {
    fn handle_packet(&self, msg: &str, udp_src_address: &UdpAddress);
}
