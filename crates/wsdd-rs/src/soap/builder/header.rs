pub(crate) mod app_sequence;
pub(crate) mod none;
pub(crate) mod reply_to_from;
use std::io::Write;

use xml::EventWriter;

pub(crate) trait WriteExtraHeaders<W>
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        std::iter::empty::<(String, String)>()
    }

    fn write_extra_headers(self, writer: &mut EventWriter<W>) -> Result<(), xml::writer::Error>;
}
