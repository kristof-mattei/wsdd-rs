use std::io::Write;

use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::config::Config;
use crate::constants;
use crate::soap::builder::WriteBody;
use crate::soap::builder::body::add_endpoint_reference;
use crate::wsd::device::DeviceUri;

pub struct Resolve<'e> {
    endpoint: &'e DeviceUri,
}

impl<'e> Resolve<'e> {
    pub fn new(endpoint: &'e DeviceUri) -> Self {
        Self { endpoint }
    }
}

impl<W> WriteBody<W> for Resolve<'_>
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        [("wsd", constants::XML_WSD_NAMESPACE)].into_iter()
    }

    fn write_body(
        self,
        _config: &Config,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("wsd:Resolve"))?;

        add_endpoint_reference(writer, self.endpoint)?;

        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
