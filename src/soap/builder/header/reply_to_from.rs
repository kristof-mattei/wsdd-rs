use std::io::Write;

use xml::writer::XmlEvent;

use crate::constants;
use crate::soap::builder::WriteExtraHeaders;
use crate::wsd::device::DeviceUri;

pub struct ReplyToFrom<'s> {
    urn: &'s DeviceUri,
}

impl<'s> ReplyToFrom<'s> {
    pub fn new(urn: &'s DeviceUri) -> Self {
        Self { urn }
    }
}

impl<W> WriteExtraHeaders<W> for ReplyToFrom<'_>
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        [("wsa", constants::XML_WSA_NAMESPACE)].into_iter()
    }

    fn write_extra_headers(
        self,
        writer: &mut xml::EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("wsa:ReplyTo"))?;
        writer.write(XmlEvent::start_element("wsa:Address"))?;
        writer.write(XmlEvent::Characters(constants::WSA_ANON))?;
        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::end_element())?;

        writer.write(XmlEvent::start_element("wsa:From"))?;
        writer.write(XmlEvent::start_element("wsa:Address"))?;
        writer.write(XmlEvent::Characters(self.urn))?;
        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
