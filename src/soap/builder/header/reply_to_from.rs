use std::io::Write;

use xml::writer::XmlEvent;

use crate::constants::{WSA_ANON, XML_WSA_NAMESPACE};
use crate::soap::builder::WriteExtraHeaders;

pub struct ReplyToFrom<'s> {
    urn: &'s str,
}

impl<'s> ReplyToFrom<'s> {
    pub fn new(urn: &'s str) -> Self {
        Self { urn }
    }
}

impl<W> WriteExtraHeaders<W> for ReplyToFrom<'_>
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        [("wsa", XML_WSA_NAMESPACE)].into_iter()
    }

    fn write_extra_headers(
        self,
        writer: &mut xml::EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("wsa:ReplyTo"))?;
        writer.write(XmlEvent::start_element("wsa:Address"))?;
        writer.write(XmlEvent::Characters(WSA_ANON))?;
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
