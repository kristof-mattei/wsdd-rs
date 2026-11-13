use std::io::Write;

use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::config::Config;
use crate::soap::builder::WriteBody;

/// The `soap:Code` values of the faults that the HTTP endpoint sends, see documentation/soap12-part1.pdf, 5.4.6.
#[derive(Clone, Copy)]
pub(crate) enum FaultCode {
    VersionMismatch,
    Sender,
    Receiver,
}

impl FaultCode {
    fn as_str(self) -> &'static str {
        match self {
            FaultCode::VersionMismatch => "soap:VersionMismatch",
            FaultCode::Sender => "soap:Sender",
            FaultCode::Receiver => "soap:Receiver",
        }
    }
}

/// The faults that the HTTP endpoint sends.
pub(crate) enum Fault {
    /// See documentation/soap12-part1.pdf, 2.8 and 5.4.7.
    VersionMismatch,
    /// A malformed message, see documentation/soap12-part1.pdf, 2.8.
    Sender,
    /// See documentation/ws-addressing.pdf, 4.1, with the first sentence of its Reason, as `FDResPub` sends it.
    InvalidMessageInformationHeader,
    /// See documentation/ws-addressing.pdf, 4.2.
    MessageInformationHeaderRequired,
    /// See documentation/ws-addressing.pdf, 4.3.
    DestinationUnreachable,
    /// See documentation/ws-addressing.pdf, 4.5, with the Reason of `FDResPub`, which has no final period.
    EndpointUnavailable,
}

impl Fault {
    pub(crate) fn code(&self) -> FaultCode {
        match *self {
            Fault::VersionMismatch => FaultCode::VersionMismatch,
            Fault::Sender
            | Fault::InvalidMessageInformationHeader
            | Fault::MessageInformationHeaderRequired
            | Fault::DestinationUnreachable => FaultCode::Sender,
            Fault::EndpointUnavailable => FaultCode::Receiver,
        }
    }

    fn subcode(&self) -> Option<&'static str> {
        match *self {
            Fault::VersionMismatch | Fault::Sender => None,
            Fault::InvalidMessageInformationHeader => Some("wsa:InvalidMessageInformationHeader"),
            Fault::MessageInformationHeaderRequired => Some("wsa:MessageInformationHeaderRequired"),
            Fault::DestinationUnreachable => Some("wsa:DestinationUnreachable"),
            Fault::EndpointUnavailable => Some("wsa:EndpointUnavailable"),
        }
    }

    fn reason(&self) -> &'static str {
        match *self {
            // the Reason of documentation/soap12-part1.pdf, 5.4.7.4, Example 5
            Fault::VersionMismatch => "Version Mismatch",
            Fault::Sender => "The message is not valid.",
            Fault::InvalidMessageInformationHeader => {
                "A message information header is not valid and the message cannot be processed."
            },
            Fault::MessageInformationHeaderRequired => {
                "A required message information header, To, MessageID, or Action, is not present."
            },
            Fault::DestinationUnreachable => {
                "No route can be determined to reach the destination role defined by the WS-Addressing To."
            },
            Fault::EndpointUnavailable => {
                "The endpoint is unable to process the message at this time"
            },
        }
    }
}

/// Writes `soap:Fault` without `soap:Detail`, see documentation/soap12-part1.pdf, 5.4.
/// documentation/ws-addressing.pdf, 4.1 and 4.2, define a `[Detail]` without an element for it, and `soap:Detail` holds only elements and white space, see documentation/soap12-part1.pdf, 5.4.5.
impl<W> WriteBody<W> for Fault
where
    W: Write,
{
    fn write_body(
        self,
        _config: &Config,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("soap:Fault"))?;

        writer.write(XmlEvent::start_element("soap:Code"))?;
        writer.write(XmlEvent::start_element("soap:Value"))?;
        writer.write(XmlEvent::Characters(self.code().as_str()))?;
        writer.write(XmlEvent::end_element())?;

        if let Some(subcode) = self.subcode() {
            writer.write(XmlEvent::start_element("soap:Subcode"))?;
            writer.write(XmlEvent::start_element("soap:Value"))?;
            writer.write(XmlEvent::Characters(subcode))?;
            writer.write(XmlEvent::end_element())?;
            writer.write(XmlEvent::end_element())?;
        }

        writer.write(XmlEvent::end_element())?;

        writer.write(XmlEvent::start_element("soap:Reason"))?;
        writer.write(XmlEvent::start_element("soap:Text").attr("xml:lang", "en-US"))?;
        writer.write(XmlEvent::Characters(self.reason()))?;
        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::end_element())?;

        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
