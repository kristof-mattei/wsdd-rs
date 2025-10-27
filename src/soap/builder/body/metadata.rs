use std::io::Write;

use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::config::Config;
use crate::constants::{
    PUB_COMPUTER, WSDP_RELATIONSHIP_DIALECT, WSDP_RELATIONSHIP_TYPE_HOST, WSDP_THIS_DEVICE_DIALECT,
    WSDP_THIS_MODEL_DIALECT, XML_PNPX_NAMESPACE, XML_PUB_NAMESPACE, XML_WSDP_NAMESPACE,
    XML_WSX_NAMESPACE,
};
use crate::soap::builder::WriteBody;
use crate::soap::builder::body::add_endpoint_reference;

pub struct MetaData {}

impl MetaData {
    pub fn new() -> Self {
        Self {}
    }
}

impl<W> WriteBody<W> for MetaData
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        [
            ("pnpx", XML_PNPX_NAMESPACE),
            ("pub", XML_PUB_NAMESPACE),
            ("wsx", XML_WSX_NAMESPACE),
            ("wsdp", XML_WSDP_NAMESPACE),
        ]
        .into_iter()
    }

    fn write_body(
        self,
        config: &Config,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        // see https://msdn.microsoft.com/en-us/library/hh441784.aspx for an
        // example. Some of the properties below might be made configurable
        // in future releases.

        writer.write(XmlEvent::start_element("wsx:Metadata"))?;

        writer.write(
            XmlEvent::start_element("wsx:MetadataSection")
                .attr("Dialect", WSDP_THIS_DEVICE_DIALECT),
        )?;
        writer.write(XmlEvent::start_element("wsdp:ThisDevice"))?;

        writer.write(XmlEvent::start_element("wsdp:FriendlyName"))?;
        writer.write(XmlEvent::Characters(
            format!("WSD Device {}", config.hostname).as_str(),
        ))?;
        writer.write(XmlEvent::end_element())?;

        writer.write(XmlEvent::start_element("wsdp:FirmwareVersion"))?;
        writer.write(XmlEvent::Characters("1.0"))?;
        writer.write(XmlEvent::end_element())?;

        writer.write(XmlEvent::start_element("wsdp:SerialNumber"))?;
        writer.write(XmlEvent::Characters("1"))?;
        writer.write(XmlEvent::end_element())?;

        // close ThisDevice
        writer.write(XmlEvent::end_element())?;

        // close MetadataSection
        writer.write(XmlEvent::end_element())?;

        writer.write(
            XmlEvent::start_element("wsx:MetadataSection").attr("Dialect", WSDP_THIS_MODEL_DIALECT),
        )?;
        writer.write(XmlEvent::start_element("wsdp:ThisModel"))?;

        writer.write(XmlEvent::start_element("wsdp:Manufacturer"))?;
        writer.write(XmlEvent::Characters("wsdd"))?;
        writer.write(XmlEvent::end_element())?;

        writer.write(XmlEvent::start_element("wsdp:ModelName"))?;
        writer.write(XmlEvent::Characters("wsdd"))?;
        writer.write(XmlEvent::end_element())?;

        writer.write(XmlEvent::start_element("pnpx:DeviceCategory"))?;
        writer.write(XmlEvent::Characters("Computers"))?;
        writer.write(XmlEvent::end_element())?;

        // close ThisModel
        writer.write(XmlEvent::end_element())?;

        // close MetadataSection
        writer.write(XmlEvent::end_element())?;

        writer.write(
            XmlEvent::start_element("wsx:MetadataSection")
                .attr("Dialect", WSDP_RELATIONSHIP_DIALECT),
        )?;
        writer.write(
            XmlEvent::start_element("wsdp:Relationship").attr("Type", WSDP_RELATIONSHIP_TYPE_HOST),
        )?;

        writer.write(XmlEvent::start_element("wsdp:Host"))?;
        add_endpoint_reference(writer, &config.uuid_as_urn_str, None)?;

        writer.write(XmlEvent::start_element("wsdp:Types"))?;
        writer.write(XmlEvent::Characters(PUB_COMPUTER))?;
        writer.write(XmlEvent::end_element())?;

        writer.write(XmlEvent::start_element("wsdp:ServiceId"))?;
        writer.write(XmlEvent::Characters(&config.uuid_as_urn_str))?;
        writer.write(XmlEvent::end_element())?;

        writer.write(XmlEvent::start_element(PUB_COMPUTER))?;
        writer.write(XmlEvent::Characters(&config.full_hostname))?;
        writer.write(XmlEvent::end_element())?;

        // close Host
        writer.write(XmlEvent::end_element())?;

        // close Relationship
        writer.write(XmlEvent::end_element())?;

        // close MetadataSection
        writer.write(XmlEvent::end_element())?;

        // close MetaData
        writer.write(XmlEvent::end_element())?;

        Ok(())
    }
}
