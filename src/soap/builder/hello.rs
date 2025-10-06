use std::io::Write;
use std::net::IpAddr;

use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::constants::XML_SOAP_NAMESPACE;
use crate::soap::builder::{Builder, WriteBody};

pub struct Hello {
    xaddr: IpAddr,
}

impl Hello {
    pub fn new(xaddr: IpAddr) -> Self {
        Self { xaddr }
    }
}

impl<W> WriteBody<W> for Hello
where
    W: Write,
{
    fn write_body(
        self,
        builder: &mut Builder,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("Hello").ns("soap", XML_SOAP_NAMESPACE))?;

        builder.add_endpoint_reference(writer, None)?;

        // THINK: Microsoft does not send the transport address here due to privacy reasons. Could make this optional.
        builder.add_xaddr(writer, self.xaddr)?;

        builder.add_metadata_version(writer)?;

        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
