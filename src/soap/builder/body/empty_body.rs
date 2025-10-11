use std::io::Write;

use xml::EventWriter;

use crate::config::Config;
use crate::soap::builder::WriteBody;

#[derive(Default)]
pub struct EmptyBody {}

impl<W> WriteBody<W> for EmptyBody
where
    W: Write,
{
    fn write_body(
        self,
        _config: &Config,
        _writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        Ok(())
    }
}
