use std::io::Write;

use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::constants::{
    WSD_TYPE_DEVICE, XML_PUB_NAMESPACE, XML_SOAP_NAMESPACE, XML_WSD_NAMESPACE, XML_WSDP_NAMESPACE,
};
use crate::soap::builder::{Builder, WriteBody};

pub struct Probe {}

impl Probe {
    pub fn new() -> Self {
        Self {}
    }
}

impl<W> WriteBody<W> for Probe
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        [
            ("wsd", XML_WSD_NAMESPACE),
            ("wsdp", XML_WSDP_NAMESPACE),
            ("pub", XML_PUB_NAMESPACE),
        ]
        .into_iter()
    }

    fn write_body(
        self,
        builder: &mut Builder,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("Probe").ns("soap", XML_SOAP_NAMESPACE))?;

        builder.add_types(writer, WSD_TYPE_DEVICE)?;

        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
