use std::io::Write;
use std::net::IpAddr;

use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::constants::{
    WSD_TYPE_DEVICE_COMPUTER, XML_PUB_NAMESPACE, XML_WSD_NAMESPACE, XML_WSDP_NAMESPACE,
};
use crate::soap::builder::{Builder, WriteBody};

pub struct ResolveMatches {
    address: IpAddr,
}

impl ResolveMatches {
    pub fn new(address: IpAddr) -> Self {
        Self { address }
    }
}

impl<W> WriteBody<W> for ResolveMatches
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        [
            ("pub", XML_PUB_NAMESPACE),
            ("wsd", XML_WSD_NAMESPACE),
            ("wsdp", XML_WSDP_NAMESPACE),
        ]
        .into_iter()
    }

    fn write_body(
        self,
        builder: &mut Builder,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("wsd:ResolveMatches"))?;
        writer.write(XmlEvent::start_element("wsd:ResolveMatch"))?;

        builder.add_endpoint_reference(writer, None)?;

        builder.add_types(writer, WSD_TYPE_DEVICE_COMPUTER)?;

        builder.add_xaddr(writer, self.address)?;

        builder.add_metadata_version(writer)?;

        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
