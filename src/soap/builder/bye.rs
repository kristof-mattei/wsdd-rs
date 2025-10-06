use std::io::Write;

use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::constants::XML_WSD_NAMESPACE;
use crate::soap::builder::{Builder, WriteBody};

pub struct Bye {}

impl Bye {
    pub fn new() -> Self {
        Self {}
    }
}

impl<W> WriteBody<W> for Bye
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        [("wsd", XML_WSD_NAMESPACE)].into_iter()
    }

    fn write_body(
        self,
        builder: &mut Builder,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("Bye").ns("wsd", XML_WSD_NAMESPACE))?;

        builder.add_endpoint_reference(writer, None)?;

        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
