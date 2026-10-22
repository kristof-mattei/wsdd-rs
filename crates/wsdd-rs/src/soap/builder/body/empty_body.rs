use std::io::Write;

use xml::EventWriter;

use crate::config::Config;
use crate::soap::builder::WriteBody;

#[derive(Default)]
pub(crate) struct EmptyBody;

impl EmptyBody {
    pub(crate) fn new() -> Self {
        Self
    }
}

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
