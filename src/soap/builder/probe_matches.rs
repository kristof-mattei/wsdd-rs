use std::io::Write;

use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::constants::{
    WSD_TYPE_DEVICE_COMPUTER, XML_PUB_NAMESPACE, XML_WSD_NAMESPACE, XML_WSDP_NAMESPACE,
};
use crate::soap::builder::{Builder, WriteBody};

pub struct ProbeMatches {}

impl ProbeMatches {
    pub fn new() -> Self {
        Self {}
    }
}

impl<W> WriteBody<W> for ProbeMatches
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
        writer.write(XmlEvent::start_element("wsd:ProbeMatches"))?;
        writer.write(XmlEvent::start_element("wsd:ProbeMatch"))?;

        builder.add_endpoint_reference(writer, None)?;

        builder.add_types(writer, WSD_TYPE_DEVICE_COMPUTER)?;
        builder.add_metadata_version(writer)?;

        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
