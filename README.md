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

I _think_ we can merge `recv_socket` & `uc_send_socket` in the future.

`mc_send_socket` receives messages in `WSDClient`, unsure why
