use std::io::Write;

use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::config::Config;
use crate::constants::{WSDP_TYPE_DEVICE, XML_WSD_NAMESPACE, XML_WSDP_NAMESPACE};
use crate::soap::builder::WriteBody;
use crate::soap::builder::body::add_types;

#[derive(Default)]
pub struct Probe {}

impl Probe {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<W> WriteBody<W> for Probe
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        [("wsd", XML_WSD_NAMESPACE), ("wsdp", XML_WSDP_NAMESPACE)].into_iter()
    }

    fn write_body(
        self,
        _config: &Config,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("wsd:Probe"))?;

        add_types(writer, WSDP_TYPE_DEVICE)?;

        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
