#![cfg(test)]

use xml::EmitterConfig;
use xml::ParserConfig;

pub fn to_string_pretty(buffer: &[u8]) -> std::io::Result<String> {
    let mut output = Vec::with_capacity(buffer.len());

    to_writer_pretty(&mut output, buffer)?;

    String::from_utf8(output).map_err(to_io)
}

fn to_writer_pretty<W>(writer: &mut W, buf: &[u8]) -> std::io::Result<usize>
where
    W: std::io::Write,
{
    let reader = ParserConfig::new()
        .trim_whitespace(true)
        .ignore_comments(false)
        .create_reader(buf);

    let mut writer = EmitterConfig::new()
        .perform_indent(true)
        .normalize_empty_elements(false)
        .autopad_comments(false)
        .create_writer(writer);

    // pass-trough
    for event in reader {
        if let Some(event) = event.map_err(to_io)?.as_writer_event() {
            writer.write(event).map_err(to_io)?;
        }
    }
    Ok(buf.len())
}

fn to_io<E>(e: E) -> std::io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    std::io::Error::other(e)
}
