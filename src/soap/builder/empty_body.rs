use std::io::Write;

use xml::EventWriter;

use crate::soap::builder::{Builder, WriteBody};

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
        _builder: &mut Builder,
        _writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        Ok(())
    }
}
