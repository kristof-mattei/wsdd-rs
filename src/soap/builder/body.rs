pub mod bye;
pub mod empty_body;
pub mod hello;
pub mod probe;
pub mod probe_matches;
pub mod resolve;
pub mod resolve_matches;

use std::io::Write;
use std::net::IpAddr;

use uuid::Uuid;
use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::config::Config;
use crate::constants::WSD_HTTP_PORT;
use crate::url_ip_addr::UrlIpAddr;

pub trait WriteBody<W>
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        std::iter::empty::<(String, String)>()
    }

    fn write_body(
        self,
        config: &Config,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error>;
}

fn add_endpoint_reference<W: Write>(
    writer: &mut EventWriter<W>,
    uuid_as_str: &str,
    endpoint: Option<Uuid>,
) -> Result<(), xml::writer::Error> {
    let endpoint = endpoint.map(|endpoint| endpoint.urn().to_string());

    let endpoint = endpoint.as_deref().unwrap_or(uuid_as_str);

    writer.write(XmlEvent::start_element("wsa:EndpointReference"))?;
    writer.write(XmlEvent::start_element("wsa:Address"))?;
    writer.write(XmlEvent::Characters(endpoint))?;
    writer.write(XmlEvent::end_element())?;
    writer.write(XmlEvent::end_element())?;

    Ok(())
}

fn add_types<W>(writer: &mut EventWriter<W>, types: &str) -> Result<(), xml::writer::Error>
where
    W: Write,
{
    writer.write(XmlEvent::start_element("wsd:Types"))?;
    writer.write(XmlEvent::Characters(types))?;
    writer.write(XmlEvent::end_element())?;

    Ok(())
}

fn add_xaddr<W: Write>(
    writer: &mut EventWriter<W>,
    config: &Config,
    ip_addr: IpAddr,
) -> Result<(), xml::writer::Error> {
    let address = format!(
        "http://{}:{}/{}",
        UrlIpAddr::from(ip_addr),
        WSD_HTTP_PORT,
        config.uuid
    );

    writer.write(XmlEvent::start_element("wsd:XAddrs"))?;
    writer.write(XmlEvent::Characters(&address))?;
    writer.write(XmlEvent::end_element())?;

    Ok(())
}

fn add_metadata_version<W: Write>(writer: &mut EventWriter<W>) -> Result<(), xml::writer::Error> {
    writer.write(XmlEvent::start_element("wsd:MetadataVersion"))?;
    writer.write(XmlEvent::Characters("1"))?;
    writer.write(XmlEvent::end_element())?;

    Ok(())
}
