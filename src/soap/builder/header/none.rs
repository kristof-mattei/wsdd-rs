use std::io::Write;

use crate::soap::builder::WriteExtraHeaders;

pub struct NoExtraHeaders {}

impl NoExtraHeaders {
    pub fn new() -> Self {
        Self {}
    }
}

impl<W> WriteExtraHeaders<W> for NoExtraHeaders
where
    W: Write,
{
    fn write_extra_headers(
        self,
        _writer: &mut xml::EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        Ok(())
    }
}
