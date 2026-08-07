use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{ArgAction, Parser};
use color_eyre::eyre;
use tracing::{Level, event};
use uuid::Uuid;
use uuid::fmt::Urn;

use crate::config::{BindTo, Config, PortOrSocket};
use crate::ffi::listen_fds;
use crate::security::parse_userspec;
use crate::wsd::device::DeviceUri;

#[expect(clippy::struct_excessive_bools, reason = "CLI flags")]
#[derive(Parser)]
#[command(
    about,
    version = concat!("v", env!("CARGO_PKG_VERSION")),
    long_version = concat!("- Web Service Discovery Daemon, v", env!("CARGO_PKG_VERSION")),
    color = clap::ColorChoice::Always
)]
struct CliArgs {
    #[arg(short, long, help = "interface or address to use")]
    interface: Vec<String>,

    #[arg(
        short = 'H',
        long,
        default_value_t = 1,
        help = "limit for multicast packets"
    )]
    hoplimit: u8,

    #[arg(short = 'U', long, help = "UUID for the target device")]
    uuid: Option<Uuid>,

    #[arg(short, long, action = ArgAction::Count, help = "increase verbosity")]
    verbose: u8,

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

    #[arg(short, long, help = "log only level and message")]
    shortlog: bool,

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

    #[arg(long, default_value = "2.0", value_parser = float_to_duration_parser, help = "set timeout for HTTP-based metadata exchange")]
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

pub fn parse_cli() -> Result<Config, eyre::Report> {
    parse_cli_from(env::args_os())
}

pub fn parse_cli_from<I, T>(from: I) -> Result<Config, eyre::Report>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    // TODO: How do we return a specific error (e.g. 3 for the user spec's value parser) when an error occurs?
    let args = CliArgs::try_parse_from(from)?;

    let interfaces: Vec<Box<str>> = if args.interface.is_empty() {
        event!(Level::WARN, "no interface given, using all interfaces");

        vec![]
    } else {
        args.interface
            .into_iter()
            .map(String::into_boxed_str)
            .collect()
    };

    let hostname = if let Some(hostname) = args.hostname {
        hostname.into_boxed_str()
    } else {
        let hostname = gethostname()?;

        hostname
            .split_once('.')
            .map(|(first, _rest)| Box::from(first))
            .unwrap_or(hostname)
    };

    let verbosity = match args.verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        _ => Level::DEBUG,
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

        format!("{}/Workgroup:{}", hostname, args.workgroup)
    };

    let bind_to = if args.ipv4only {
        BindTo::IPv4
    } else if args.ipv6only {
        BindTo::IPv6
    } else {
        BindTo::DualStack
    };

    let config = Config {
        interfaces,
        hoplimit: args.hoplimit,
        uuid,
        uuid_as_device_uri,
        verbosity,
        hostname,
        full_hostname: full_hostname.into_boxed_str(),
        no_autostart: args.no_autostart,
        no_http: args.no_http,
        bind_to,
        shortlog: args.shortlog,
        chroot: args.chroot,
        user: args.user,
        discovery: args.discovery,
        listen,
        no_host: args.no_host,
        metadata_timeout: args.metadata_timeout,
        source_port: args.source_port,
        wsd_instance_id: now().as_secs().to_string().into_boxed_str(),
        sequence_id: sequence_id().to_string().into_boxed_str(),
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

fn to_listen(listen: &str) -> Result<PortOrSocket, String> {
    // if listen is numeric, it's try and parse it as a port
    let all_numeric = listen.chars().all(char::is_numeric);

    if all_numeric {
        let listen =
            (listen.parse::<u16>()).map_err(|_| "number too large to fit in u16".to_owned())?;

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
    use std::path::Path;

    use pretty_assertions::{assert_eq, assert_matches};
    use tracing::Level;

    use crate::cli::{parse_cli_from, to_listen};
    use crate::config::PortOrSocket;

    #[test]
    fn interfaces() {
        let config =
            parse_cli_from(["wsdd-rs", "--interface", "eth0", "--interface", "eth1"]).unwrap();

        assert_eq!(
            config
                .interfaces
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>(),
            &["eth0", "eth1"]
        );
    }

    #[test]
    fn no_verbose() {
        let config = parse_cli_from(["wsdd-rs"]).unwrap();

        assert_eq!(config.verbosity, Level::WARN);
    }

    #[test]
    fn verbose() {
        let config = parse_cli_from(["wsdd-rs", "--verbose"]).unwrap();

        assert_eq!(config.verbosity, Level::INFO);
    }

    #[test]
    fn very_verbose() {
        let config = parse_cli_from(["wsdd-rs", "--verbose", "--verbose"]).unwrap();

        assert_eq!(config.verbosity, Level::DEBUG);
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
            Some("number too large to fit in u16")
        );
    }
}
