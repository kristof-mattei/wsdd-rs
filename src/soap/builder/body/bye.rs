use std::io::Write;

use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::config::Config;
use crate::constants::XML_WSD_NAMESPACE;
use crate::soap::builder::WriteBody;
use crate::soap::builder::body::add_endpoint_reference;

#[derive(Default)]
pub struct Bye {}

impl Bye {
    pub fn new() -> Self {
        Self::default()
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
        config: &Config,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("wsd:Bye"))?;

        add_endpoint_reference(writer, &config.uuid_as_device_uri)?;

        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
