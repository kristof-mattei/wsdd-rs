use std::io::Write;

use xml::writer::XmlEvent;

use crate::constants;
use crate::soap::builder::WriteExtraHeaders;

pub struct AppSequence<'s> {
    wsd_instance_id: &'s str,
    sequence_id: &'s str,
    message_number: u64,
}

impl<'s> AppSequence<'s> {
    pub fn new(wsd_instance_id: &'s str, sequence_id: &'s str, message_number: u64) -> Self {
        Self {
            wsd_instance_id,
            sequence_id,
            message_number,
        }
    }
}

impl<W> WriteExtraHeaders<W> for AppSequence<'_>
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        [("wsd", constants::XML_WSD_NAMESPACE)].into_iter()
    }

    fn write_extra_headers(
        self,
        writer: &mut xml::EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        let wsd_instance_id = self.wsd_instance_id;
        let sequence_id = self.sequence_id;
        let message_number = self.message_number.to_string();

        writer.write(
            XmlEvent::start_element("wsd:AppSequence")
                .attr("InstanceId", wsd_instance_id)
                .attr("SequenceId", sequence_id)
                .attr("MessageNumber", &message_number),
        )?;

        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
