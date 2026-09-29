use std::io::Write;

use xml::writer::XmlEvent;

use crate::config::AppSequence;
use crate::constants;
use crate::soap::builder::WriteExtraHeaders;

pub struct AppSequenceHeader<'s> {
    app_sequence: &'s AppSequence,
    message_number: u64,
}

impl<'s> AppSequenceHeader<'s> {
    pub fn next(app_sequence: &'s AppSequence) -> Self {
        Self {
            app_sequence,
            message_number: app_sequence.next_message_number(),
        }
    }
}

impl<W> WriteExtraHeaders<W> for AppSequenceHeader<'_>
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
        let instance_id = self.app_sequence.instance_id().to_string();
        let message_number = self.message_number.to_string();

        writer.write(
            XmlEvent::start_element("wsd:AppSequence")
                .attr("InstanceId", &instance_id)
                .attr("SequenceId", self.app_sequence.sequence_id())
                .attr("MessageNumber", &message_number),
        )?;

        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
