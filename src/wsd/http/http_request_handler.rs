pub struct WSDHttpRequestHandler {}
// class WSDHttpRequestHandler(http.server.BaseHTTPRequestHandler):
//     """Class for handling WSD requests coming over HTTP"""

//     def log_message(self, fmt, *args) -> None:
//         logger.info("{} - - ".format(self.address_string()) + fmt % args)

//     def do_POST(self) -> None:
//         if self.path != '/' + str(args.uuid):
//             self.send_error(http.HTTPStatus.NOT_FOUND)

//         ct = self.headers['Content-Type']
//         if ct is None or not ct.startswith(MIME_TYPE_SOAP_XML):
//             self.send_error(http.HTTPStatus.BAD_REQUEST, 'Invalid Content-Type')

//         content_length = int(self.headers['Content-Length'])
//         body = self.rfile.read(content_length)

//         response = self.server.wsd_handler.handle_message(body)  # type: ignore
//         if response:
//             self.send_response(http.HTTPStatus.OK)
//             self.send_header('Content-Type', MIME_TYPE_SOAP_XML)
//             self.end_headers()
//             self.wfile.write(response.encode('utf-8'))
//         else:
//             self.send_error(http.HTTPStatus.BAD_REQUEST)
