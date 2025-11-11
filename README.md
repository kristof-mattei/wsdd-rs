# TODO

- TODOs in the code
- Support SOAP 1.2: `http://www.w3.org/2003/05/soap-envelope` & SOAP 1.1: `http://schemas.xmlsoap.org/soap/envelope/` (Notice trailing slash)
- Validate UDP flows (see https://learn.microsoft.com/pdf?url=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Fwindows%2Fwin32%2Fwsdapi%2Ftoc.json), also stored in [./documentation/windows-win32-wsdapi.pdf](./documentation/windows-win32-wsdapi.pdf), move to docs when done

XSD validation:

```
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://www.w3.org/2003/05/soap-envelope http://www.w3.org/2003/05/soap-envelope
                        http://schemas.xmlsoap.org/ws/2005/04/discovery http://schemas.xmlsoap.org/ws/2005/04/discovery/ws-discovery.xsd"
```

- Backport code since 147c9039630afd2bc6a73f1a04d5e6526947d90b (https://github.com/christgau/wsdd/commits/master/)

# Information, docs

- Debugging: https://learn.microsoft.com/en-us/windows/win32/wsdapi/inspecting-network-traces-for-udp-ws-discovery

- Online spec: https://specs.xmlsoap.org/ws/2005/04/discovery/ws-discovery.pdf (also stored in [./documentation/ws-discovery](./documentation/ws-discovery.pdf))

- More definitions: https://learn.microsoft.com/en-us/windows/win32/wsdapi/discovery-and-metadata-exchange-message-patterns

- Interopability tool: https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/wsdapi-basic-interoperability-tool

# Socket descriptions

- `recv_socket` RECEIVES multicast messages, SENDS unicast, by binding to the multicast address, on the WSD Port
- `mc_send_socket` SENDS multicast messages, on a custom port, RECEIVES unicast
- `uc_send_socket` is used REPLY with unicast, it is bound to the interface's address, on the WSD Port

The sockets are separate for a reason: https://github.com/christgau/wsdd/commit/ee8783ce71a408a3d9923b5d67659f7ce2712166

`mc_send_socket` receives messages in `WSDClient`, because it sends out a probe over the `mc_send_socket`, and hosts reply FROM 3072 (in our case `uc_send_socket` TO the `mc_send_socket`, that port)

# Questions

- Client mode: Why is it, that when we get a `Hello` without `Xaddr`, to which we respond with a `Resolve`, we get a resolve FROM the host?

## License

MIT, see [LICENSE](./LICENSE)

`SPDX-License-Identifier: MIT`
