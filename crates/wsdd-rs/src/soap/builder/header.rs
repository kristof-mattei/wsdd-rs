pub mod app_sequence;
pub mod none;
pub mod reply_to_from;
use std::io::Write;

use xml::EventWriter;

pub trait WriteExtraHeaders<W>
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        std::iter::empty::<(String, String)>()
    }

    fn write_extra_headers(self, writer: &mut EventWriter<W>) -> Result<(), xml::writer::Error>;
}
