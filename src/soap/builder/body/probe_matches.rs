use std::io::Write;

use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::config::Config;
use crate::constants;
use crate::soap::builder::WriteBody;
use crate::soap::builder::body::{add_endpoint_reference, add_metadata_version, add_types};

#[derive(Default)]
pub struct ProbeMatches {}

impl ProbeMatches {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<W> WriteBody<W> for ProbeMatches
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
        writer.write(XmlEvent::start_element("wsd:ProbeMatches"))?;
        writer.write(XmlEvent::start_element("wsd:ProbeMatch"))?;

        add_endpoint_reference(writer, &config.uuid_as_device_uri)?;
        add_types(writer, constants::WSDP_TYPE_DEVICE_COMPUTER)?;
        add_metadata_version(writer)?;

        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
