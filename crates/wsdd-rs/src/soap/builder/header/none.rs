use std::io::Write;

use crate::soap::builder::WriteExtraHeaders;

#[derive(Default)]
pub(crate) struct NoExtraHeaders;

impl NoExtraHeaders {
    pub(crate) fn new() -> Self {
        Self
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
