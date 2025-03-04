#[expect(unused)]
struct ApiServer {}
// class ApiServer:

//     address_monitor: 'NetworkAddressMonitor'

//     def __init__(self, aio_loop: asyncio.AbstractEventLoop, listen_address: bytes,
//                  address_monitor: 'NetworkAddressMonitor') -> None:
//         self.server = None
//         self.address_monitor = address_monitor

//         # defer server creation
//         self.create_task = aio_loop.create_task(self.create_server(aio_loop, listen_address))

//     async def create_server(self, aio_loop: asyncio.AbstractEventLoop, listen_address: Any) -> None:

//         # It appears mypy is not able to check the argument to create_task and the return value of start_server
//         # correctly. The docs say start_server returns a coroutine and the create_task takes a coro. And: It works.
//         # Thus, we ignore type errors here.
//         if isinstance(listen_address, int) or listen_address.isnumeric():
//             self.server = await aio_loop.create_task(
//                 asyncio.start_server(  # type: ignore
//                     self.on_connect,
//                     host='localhost',
//                     port=int(listen_address),
//                     reuse_address=True,
//                     reuse_port=True))
//         else:
//             self.server = await aio_loop.create_task(
//                 asyncio.start_unix_server(  # type: ignore
//                     self.on_connect, path=listen_address))

//     async def on_connect(self, read_stream: asyncio.StreamReader, write_stream: asyncio.StreamWriter) -> None:
//         while True:
//             try:
//                 line = await read_stream.readline()
//                 if line:
//                     self.handle_command(str(line.strip(), 'utf-8'), write_stream)
//                     if not write_stream.is_closing():
//                         await write_stream.drain()
//                 else:
//                     write_stream.close()
//                     return
//             except UnicodeDecodeError as e:
//                 logger.debug('invalid input utf8', e)
//             except Exception as e:
//                 logger.warning('exception in API client', e)
//                 write_stream.close()
//                 return

//     def handle_command(self, line: str, write_stream: asyncio.StreamWriter) -> None:
//         words = line.split()
//         if len(words) == 0:
//             return

//         command = words[0]
//         command_args = words[1:]
//         if command == 'probe' and args.discovery:
//             intf = command_args[0] if command_args else None
//             logger.debug('probing devices on {} upon request'.format(intf))
//             for client in self.get_clients_by_interface(intf):
//                 client.send_probe()
//         elif command == 'clear' and args.discovery:
//             logger.debug('clearing list of known devices')
//             WSDDiscoveredDevice.instances.clear()
//         elif command == 'list' and args.discovery:
//             wsd_type = command_args[0] if command_args else None
//             write_stream.write(bytes(self.get_list_reply(wsd_type), 'utf-8'))
//         elif command == 'quit':
//             write_stream.close()
//         elif command == 'start':
//             self.address_monitor.enumerate()
//         elif command == 'stop':
//             self.address_monitor.teardown()
//         else:
//             logger.debug('could not handle API request: {}'.format(line))

//     def get_clients_by_interface(self, interface: Optional[str]) -> List[WSDClient]:
//         return [c for c in WSDClient.instances if c.mch.address.interface.name == interface or not interface]

//     def get_list_reply(self, wsd_type: Optional[str]) -> str:
//         retval = ''
//         for dev_uuid, dev in WSDDiscoveredDevice.instances.items():
//             if wsd_type and (wsd_type not in dev.types):
//                 continue

//             addrs_str = []
//             for addrs in dev.addresses.items():
//                 addrs_str.append(', '.join(['{}'.format(a) for a in addrs]))

//             retval = retval + '{}\t{}\t{}\t{}\t{}\t{}\n'.format(
//                 dev_uuid, dev.display_name, dev.props['BelongsTo'] if 'BelongsTo' in dev.props else '',
//                 datetime.datetime.fromtimestamp(dev.last_seen).isoformat('T', 'seconds'), ','.join(addrs_str), ','.join(
//                     dev.types))

//         retval += '.\n'
//         return retval

//     async def cleanup(self) -> None:
//         # ensure the server is not created after we have teared down
//         await self.create_task
//         if self.server:
//             self.server.close()
//             await self.server.wait_closed()
