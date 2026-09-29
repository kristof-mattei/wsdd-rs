use std::io::Write;
use std::net::IpAddr;

use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::config::Config;
use crate::constants;
use crate::soap::builder::WriteBody;
use crate::soap::builder::body::{
    add_endpoint_reference, add_metadata_version, add_types, add_xaddr,
};

pub struct Hello {
    xaddr: IpAddr,
}

impl Hello {
    pub fn new(xaddr: IpAddr) -> Self {
        Self { xaddr }
    }
}

impl<W> WriteBody<W> for Hello
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        [
            ("pub", constants::XML_PUB_NAMESPACE),
            ("wsd", constants::XML_WSD_NAMESPACE),
            ("wsdp", constants::XML_WSDP_NAMESPACE),
        ]
        .into_iter()
    }

    fn write_body(
        self,
        config: &Config,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("wsd:Hello"))?;

        // element order is the `HelloType` sequence, see documentation/ws-discovery.pdf, Appendix II
        add_endpoint_reference(writer, &config.uuid_as_device_uri)?;

        // Technically `Types` are optional in `Hello`, but omitted `Types` have no implied value, so a client could only match us by Type after a `Probe` or `Resolve`, see documentation/ws-discovery.pdf, Section 4.1
        // omitting them hides nothing, because `ProbeMatch` and `ResolveMatch` return the same `Types`
        add_types(writer, constants::WSDP_TYPE_DEVICE_COMPUTER)?;

        // WSDAPI sends one identical `Hello` on every interface, so `XAddrs` in it would list the addresses of every network the host is on, on each of those networks, and WSDAPI omits `XAddrs` instead, see documentation/windows-win32-wsdapi.pdf, "Hello and XAddrs" and "Discovery in a multi-homed environment"
        // each address here sends its own `Hello` from that address, so the datagram's source address already reveals the address in `XAddrs`, and omitting it would only cost clients a `Resolve` round trip
        add_xaddr(writer, config, self.xaddr)?;

        add_metadata_version(writer)?;

        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
