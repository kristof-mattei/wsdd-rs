#![cfg(test)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use libc::RT_SCOPE_SITE;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::cli;
use crate::config::Config;
use crate::max_size_deque::MaxSizeDeque;
use crate::network_address::NetworkAddress;
use crate::network_interface::NetworkInterface;
use crate::soap::parser::MessageHandler;

pub mod xml {
    use xml::{EmitterConfig, ParserConfig};

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

        // pass-through
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
}

pub fn build_config(endpoint_uuid: Uuid, instance_id: &str) -> Config {
    let mut config = cli::parse_cli_from([
        "-4",
        "--uuid",
        &endpoint_uuid.to_string(),
        "--hostname",
        "test-host-name",
    ])
    .unwrap();

    // instance ID is not settable with commandline
    config.wsd_instance_id = Box::from(instance_id);

    config
}

pub fn build_message_handler() -> MessageHandler {
    MessageHandler::new(
        Arc::new(RwLock::new(MaxSizeDeque::new(20))),
        NetworkAddress::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1)),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        ),
    )
}

pub fn build_message_handler_with_network_address(
    ip_address: IpAddr,
) -> (MessageHandler, NetworkAddress) {
    let network_address = NetworkAddress::new(
        ip_address,
        Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
    );

    (
        MessageHandler::new(
            Arc::new(RwLock::new(MaxSizeDeque::new(20))),
            network_address.clone(),
        ),
        network_address,
    )
}

#[cfg(test)]
mod tests {
    use crate::test_utils::xml::to_string_pretty;

    #[test]
    fn invalid_xml_yields_error() {
        let invalid = "<open>contents</not_closed";

        let pretty = to_string_pretty(invalid.as_bytes());

        pretty.unwrap_err();
    }
}
