use std::io::Write;

use xml::writer::XmlEvent;

use crate::soap::builder::WriteExtraHeaders;

/// The `soap:Upgrade` header block of a `soap:VersionMismatch` fault, see documentation/soap12-part1.pdf, 5.4.7.
pub(crate) struct Upgrade;

impl Upgrade {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl<W> WriteExtraHeaders<W> for Upgrade
where
    W: Write,
{
    fn write_extra_headers(
        self,
        writer: &mut xml::EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("soap:Upgrade"))?;
        // `soap:Envelope` declares the `soap` prefix of the value, see documentation/soap12-part1.pdf, 5.4.7.3
        writer.write(
            XmlEvent::start_element("soap:SupportedEnvelope").attr("qname", "soap:Envelope"),
        )?;
        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
