use std::io::Write;

use uuid::Uuid;
use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::constants::XML_WSD_NAMESPACE;
use crate::soap::builder::{Builder, WriteBody};

pub struct Resolve {
    endpoint: Uuid,
}

impl Resolve {
    pub fn new(endpoint: Uuid) -> Self {
        Self { endpoint }
    }
}

impl<W> WriteBody<W> for Resolve
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
        writer.write(XmlEvent::start_element("wsd:Resolve"))?;

        builder.add_endpoint_reference(writer, Some(self.endpoint))?;

        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
