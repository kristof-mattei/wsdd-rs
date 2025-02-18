use std::sync::Arc;

use crate::config::Config;
use crate::multicast_handler::MulticastHandler;
use crate::wsd::message_handler::WSDMessageHandler;

pub(crate) struct WSDUDPMessageHandler {
    multicast_handler: Arc<MulticastHandler>,
    message_handler: WSDMessageHandler,
}

impl WSDUDPMessageHandler {
    pub fn new(multicast_handler: &Arc<MulticastHandler>, config: &Arc<Config>) -> Self {
        Self {
            multicast_handler: Arc::clone(multicast_handler),
            message_handler: WSDMessageHandler::new(config),
        }
    }
}

// class WSDUDPMessageHandler(WSDMessageHandler):
//     """
//     A message handler that handles traffic received via MutlicastHandler.
//     """

//     mch: MulticastHandler
//     tearing_down: bool

//     def __init__(self, mch: MulticastHandler) -> None:
//         super().__init__()

//         self.mch = mch
//         self.tearing_down = False

//     def teardown(self):
//         self.tearing_down = True

//     def send_datagram(self, msg: str, dst: UdpAddress) -> None:
//         try:
//             self.mch.send(msg.encode('utf-8'), dst)
//         except Exception as e:
//             logger.error('error while sending packet on {}: {}'.format(self.mch.address.interface, e))

//     def enqueue_datagram(self, msg: str, address: UdpAddress, msg_type: Optional[str] = None) -> None:
//         if msg_type:
//             logger.info('scheduling {0} message via {1} to {2}'.format(msg_type, address.interface, address))

//         schedule_task = self.mch.aio_loop.create_task(self.schedule_datagram(msg, address))
//         # Add this task to the pending list during teardown to wait during shutdown
//         if self.tearing_down:
//             self.pending_tasks.append(schedule_task)

//     async def schedule_datagram(self, msg: str, address: UdpAddress) -> None:
//         """
//         Schedule to send the given message to the given address.

//         Implements SOAP over UDP, Appendix I.
//         """

//         self.send_datagram(msg, address)

//         delta = 0
//         msg_count = MULTICAST_UDP_REPEAT if address == self.mch.multicast_address else UNICAST_UDP_REPEAT
//         delta = random.randint(UDP_MIN_DELAY, UDP_MAX_DELAY)
//         for i in range(msg_count - 1):
//             await asyncio.sleep(delta / 1000.0)
//             self.send_datagram(msg, address)
//             delta = min(delta * 2, UDP_UPPER_DELAY)
