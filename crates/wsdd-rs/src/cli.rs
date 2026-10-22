#[cfg(test)]
use std::ffi::OsString;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use color_eyre::eyre;
use tracing::{Level, event};
use uuid::Uuid;
use uuid::fmt::Urn;

use crate::config::{AppSequence, BindTo, Config, InterfaceFilter, PortOrSocket};
use crate::ffi::listen_fds;
use crate::network_interface::DevName;
use crate::security::parse_userspec;
use crate::soap::InstanceId;
use crate::wsd::device::DeviceUri;

#[expect(clippy::struct_excessive_bools, reason = "CLI flags")]
#[derive(Parser)]
#[command(about, version)]
pub(crate) struct Cli {
    #[arg(short, long, value_parser = to_interface_filter, help = "interface, address or scoped IPv6 address such as `fe80::1%eth0` to use")]
    interface: Vec<InterfaceFilter>,

    #[arg(
        short = 'H',
        long,
        default_value_t = 1,
        help = "limit for multicast packets"
    )]
    hoplimit: u8,

    #[arg(short = 'U', long, help = "UUID for the target device")]
    uuid: Option<Uuid>,

    #[arg(
        short,
        long,
        group = "domain-workgroup",
        help = "set domain name (disables workgroup)"
    )]
    domain: Option<String>,

    #[arg(short = 'n', long, help = "override (NetBIOS) hostname to be used")]
    hostname: Option<String>,

    #[arg(
        short,
        long,
        group = "domain-workgroup",
        default_value = "WORKGROUP",
        help = "set workgroup name"
    )]
    workgroup: String,

    #[arg(short = 'A', long, help = "do not start networking after launch")]
    no_autostart: bool,

    #[arg(short = 't', long, help = "disable http service (e.g. for debugging)")]
    no_http: bool,

    #[arg(short = '4', long, group = "ip", help = "use only IPv4")]
    ipv4only: bool,

    #[arg(short = '6', long, group = "ip", help = "use only IPv6")]
    ipv6only: bool,

    #[arg(short, long, help = "preserve case of the provided/detected hostname")]
    preserve_case: bool,

    #[arg(short, long, help = "directory to chroot into")]
    chroot: Option<PathBuf>,

    #[arg(short, long, value_parser = parse_userspec, help = "drop privileges to user:group")]
    user: Option<(u32, u32)>,

    #[arg(short = 'D', long, help = "enable discovery operation mode")]
    discovery: bool,

    #[arg(short, long, value_parser = to_listen, help = "listen on path or localhost port in discovery mode")]
    listen: Option<PortOrSocket>,

    #[arg(
        short = 'o',
        long,
        help = "disable server mode operation (host will be undiscoverable)"
    )]
    no_host: bool,

    #[arg(long, default_value = "30.0", value_parser = float_to_duration_parser, help = "set timeout for HTTP-based metadata exchange")]
    metadata_timeout: Duration,

    #[arg(
        long,
        default_value_t = 0,
        help = "send multicast traffic/receive replies on this port"
    )]
    source_port: u16,
}

fn float_to_duration_parser(value: &str) -> Result<Duration, String> {
    let value = value.parse::<f32>().map_err(|error| error.to_string())?;

    Duration::try_from_secs_f32(value).map_err(|error| error.to_string())
}

#[cfg(test)]
pub(crate) fn parse_cli_from<I, T>(from: I) -> Result<Config, eyre::Report>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    to_config(Cli::try_parse_from(from)?)
}

pub(crate) fn to_config(args: Cli) -> Result<Config, eyre::Report> {
    if args.interface.is_empty() {
        event!(Level::WARN, "no interface given, using all interfaces");
    }

    let hostname = if let Some(hostname) = args.hostname {
        hostname.into_boxed_str()
    } else {
        let hostname = gethostname()?;

        hostname
            .split_once('.')
            .map(|(first, _rest)| Box::from(first))
            .unwrap_or(hostname)
    };

    let uuid = match args.uuid {
        Some(uuid) => uuid,
        None => get_uuid_from_machine()?,
    };

    let uuid_as_device_uri = DeviceUri::new(uuid.urn().to_string().into_boxed_str());

    let listen = args.listen.or_else(|| match listen_fds(true) {
        Ok(fds) => fds.first().map(|&fd| PortOrSocket::Socket(fd)),
        Err(error) => {
            event!(Level::ERROR, ?error, "Error receiving file descriptors");

            None
        },
    });

    let full_hostname = if let Some(domain) = args.domain {
        // for `domain` the default is to lowercase the `hostname`
        let hostname = if args.preserve_case {
            &*hostname
        } else {
            &*hostname.to_lowercase()
        };
        format!("{}/Domain:{}", hostname, domain)
    } else {
        // for `workgroup` the default is to UPPERCASE the `hostname`
        let hostname = if args.preserve_case {
            &*hostname
        } else {
            &*hostname.to_uppercase()
        };

        format!("{}/Workgroup:{}", hostname, args.workgroup.to_uppercase())
    };

    let bind_to = if args.ipv4only {
        BindTo::IPv4
    } else if args.ipv6only {
        BindTo::IPv6
    } else {
        BindTo::DualStack
    };

    let config = Config {
        interfaces: args.interface,
        hoplimit: args.hoplimit,
        uuid,
        uuid_as_device_uri,
        hostname,
        full_hostname: full_hostname.into_boxed_str(),
        no_autostart: args.no_autostart,
        no_http: args.no_http,
        bind_to,
        chroot: args.chroot,
        user: args.user,
        discovery: args.discovery,
        listen,
        no_host: args.no_host,
        metadata_timeout: args.metadata_timeout,
        source_port: args.source_port,
        app_sequence: AppSequence::new(
            InstanceId::new(now().as_secs()),
            sequence_id().to_string().into_boxed_str(),
        ),
    };

    Ok(config)
}

fn now() -> Duration {
    #[cfg(miri)]
    {
        Duration::from_secs(1_762_802_693)
    }

    #[cfg(not(miri))]
    {
        use std::time::SystemTime;

        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Before epoch? Time travel?")
    }
}

#[cfg_attr(
    not(test),
    expect(
        clippy::cfg_not_test,
        reason = "Adding in the ability to control UUID generation seems excessive"
    )
)]
fn sequence_id() -> Urn {
    #[cfg(test)]
    {
        Uuid::nil().urn()
    }

    #[cfg(not(test))]
    {
        Uuid::now_v7().urn()
    }
}

fn to_interface_filter(value: &str) -> Result<InterfaceFilter, String> {
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(InterfaceFilter::Address(address));
    }

    if let Some((address, zone)) = value.split_once('%')
        && let Ok(address) = address.parse::<Ipv6Addr>()
    {
        if !address.is_unicast_link_local() {
            return Err(format!(
                "invalid zone in `{}`: zones only apply to link-local addresses",
                value
            ));
        }

        let zone = DevName::try_from(Box::from(zone))
            .map_err(|error| format!("invalid zone in `{}`: {}", value, error))?;

        return Ok(InterfaceFilter::ScopedAddress { address, zone });
    }

    DevName::try_from(Box::from(value))
        .map(InterfaceFilter::Name)
        .map_err(|error| {
            if is_alias_label(value) {
                format!(
                    "{}, alias labels like `eth0:0` are not supported yet",
                    error
                )
            } else {
                error.to_string()
            }
        })
}

fn is_alias_label(value: &str) -> bool {
    value.split_once(':').is_some_and(|(name, label)| {
        !label.is_empty() && !label.contains(':') && DevName::try_from(Box::from(name)).is_ok()
    })
}

fn to_listen(listen: &str) -> Result<PortOrSocket, String> {
    // ASCII digits are a port, anything else is a socket path
    if listen.chars().all(|c| c.is_ascii_digit()) {
        let listen = listen.parse::<u16>().map_err(|error| error.to_string())?;

        Ok(PortOrSocket::Port(listen))
    } else {
        Ok(PortOrSocket::SocketPath(PathBuf::from(listen)))
    }
}

fn gethostname() -> Result<Box<str>, eyre::Report> {
    #[cfg(miri)]
    fn gethostname() -> Result<Box<str>, eyre::Report> {
        Ok(Box::from("hostname"))
    }

    #[cfg(not(miri))]
    fn gethostname() -> Result<Box<str>, eyre::Report> {
        use std::ffi::CStr;
        use std::io::Error;

        let mut buffer = [0_u8; 255 /* POSIX LIMIT */ + 1 /* for the \0 */];

        // SAFETY: libc call
        let length = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };

        if length == -1 {
            return Err(Error::last_os_error().into());
        }

        let hostname = CStr::from_bytes_until_nul(&buffer)
            .expect("We used oversized buffer, so not finding a null is impossible")
            .to_str()?;

        Ok(String::from(hostname).into_boxed_str())
    }

    gethostname()
}

fn get_uuid_from_machine() -> Result<Uuid, eyre::Report> {
    #[cfg(miri)]
    fn read_uuid_from_file(_path: &Path) -> Option<uuid::Uuid> {
        None
    }

    #[cfg(not(miri))]
    fn read_uuid_from_file(path: &Path) -> Option<uuid::Uuid> {
        let content = std::fs::read_to_string(path).ok()?;

        uuid::Uuid::try_parse(content.trim()).ok()
    }

    // machine uuid: try machine-id file first but also check for hostid (FreeBSD)
    let uuid = match read_uuid_from_file(Path::new("/etc/machine-id"))
        .or_else(|| read_uuid_from_file(Path::new("/etc/hostid")))
    {
        Some(uuid) => uuid,
        None => uuid::Uuid::new_v5(&Uuid::NAMESPACE_DNS, gethostname()?.as_bytes()),
    };

    event!(Level::INFO, %uuid, "using pre-defined UUID");

    Ok(uuid)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::path::Path;

    use pretty_assertions::{assert_eq, assert_matches};

    use crate::cli::{parse_cli_from, to_interface_filter, to_listen};
    use crate::config::{InterfaceFilter, PortOrSocket};
    use crate::network_interface::DevName;

    #[test]
    fn interfaces() {
        let config =
            parse_cli_from(["wsdd-rs", "--interface", "eth0", "--interface", "eth1"]).unwrap();

        assert_eq!(
            config.interfaces,
            &[
                InterfaceFilter::Name(DevName::try_from(Box::from("eth0")).unwrap()),
                InterfaceFilter::Name(DevName::try_from(Box::from("eth1")).unwrap())
            ]
        );
    }

    #[test]
    fn interface_values_classify_as_name_or_address() {
        assert_matches!(to_interface_filter("eth0"), Ok(InterfaceFilter::Name(n)) if n.as_ref() == "eth0");
        assert_matches!(
            to_interface_filter("eth0.100"),
            Ok(InterfaceFilter::Name(_))
        );
        assert_matches!(
            to_interface_filter(&"a".repeat(15)),
            Ok(InterfaceFilter::Name(_))
        );
        assert_matches!(
            to_interface_filter("192.168.1.5"),
            Ok(InterfaceFilter::Address(IpAddr::V4(_)))
        );
        assert_matches!(
            to_interface_filter("fe80::1"),
            Ok(InterfaceFilter::Address(IpAddr::V6(_)))
        );
    }

    #[test]
    fn interface_filters_display_as_given() {
        for value in ["eth0", "192.168.1.5", "fe80::1", "fe80::1%eth0"] {
            assert_eq!(to_interface_filter(value).unwrap().to_string(), value);
        }
    }

    #[test]
    fn invalid_interface_values_are_rejected() {
        let too_long = "a".repeat(16);

        for value in [
            "10.0.0.1%eth0",
            "",
            ".",
            "..",
            "eth 0",
            "eth/0",
            too_long.as_str(),
        ] {
            assert_eq!(
                to_interface_filter(value),
                Err(format!("`{}` is not a valid interface name", value))
            );
        }
    }

    #[test]
    fn scoped_ipv6_addresses_are_parsed() {
        for zone in ["eth0", "2"] {
            assert_eq!(
                to_interface_filter(&format!("fe80::1%{}", zone)),
                Ok(InterfaceFilter::ScopedAddress {
                    address: "fe80::1".parse().unwrap(),
                    zone: DevName::try_from(Box::from(zone)).unwrap(),
                })
            );
        }
    }

    #[test]
    fn scoped_ipv6_address_with_an_invalid_zone_is_rejected() {
        assert_eq!(
            to_interface_filter("fe80::1%eth 0"),
            Err(String::from(
                "invalid zone in `fe80::1%eth 0`: `eth 0` is not a valid interface name"
            ))
        );
    }

    #[test]
    fn scoped_non_link_local_address_is_rejected() {
        assert_eq!(
            to_interface_filter("2001:db8::1%eth0"),
            Err(String::from(
                "invalid zone in `2001:db8::1%eth0`: zones only apply to link-local addresses"
            ))
        );
    }

    #[test]
    fn alias_labels_get_the_alias_hint() {
        assert_eq!(
            to_interface_filter("eth0:0"),
            Err(String::from(
                "`eth0:0` is not a valid interface name, alias labels like `eth0:0` are not supported yet"
            ))
        );
    }

    #[test]
    fn any_invalid_interface_value_is_an_error() {
        // valid values do not mask the invalid one
        let result = parse_cli_from(["wsdd-rs", "--interface", "eth0", "--interface", "eth0:0"]);

        assert_matches!(result, Err(_));
    }

    #[test]
    fn workgroup_is_uppercased() {
        let config =
            parse_cli_from(["wsdd-rs", "--hostname", "host", "--workgroup", "mygroup"]).unwrap();

        assert_eq!(&*config.full_hostname, "HOST/Workgroup:MYGROUP");
    }

    #[test]
    fn to_listen_port() {
        let port = to_listen("1234");

        assert_matches!(port, Ok(PortOrSocket::Port(1234)));
    }

    #[test]
    fn to_listen_socket() {
        let path = "/var/wsdd-rs/socket";

        let port = to_listen(path);

        assert_matches!(port, Ok(PortOrSocket::SocketPath(p)) if p == Path::new(path));
    }

    #[test]
    fn to_listen_port_too_large() {
        let port = to_listen("123456");

        assert_matches!(
            port.err().as_deref(),
            Some("number too large to fit in target type")
        );
    }

    #[test]
    fn to_listen_non_ascii_digits_socket() {
        // Arabic-Indic digits 123, only ASCII digits count as a port
        let path = "\u{661}\u{662}\u{663}";

        let port = to_listen(path);

        assert_matches!(port, Ok(PortOrSocket::SocketPath(p)) if p == Path::new(path));
    }

    #[test]
    fn to_listen_empty() {
        let port = to_listen("");

        assert_matches!(
            port.err().as_deref(),
            Some("cannot parse integer from empty string")
        );
    }
}
