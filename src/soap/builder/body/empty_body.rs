use std::io::Write;

use xml::EventWriter;

use crate::config::Config;
use crate::soap::builder::WriteBody;

pub struct EmptyBody {}

impl EmptyBody {
    pub fn new() -> Self {
        Self {}
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
