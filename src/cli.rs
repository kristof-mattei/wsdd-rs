use core::str;
use std::env;
use std::ffi::{CStr, OsString};
use std::io::Error;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::parser::ValueSource;
use clap::{Arg, ArgAction, Command, command, value_parser};
use color_eyre::eyre;
use tracing::{Level, event};
use uuid::Uuid;

use crate::config::{Config, PortOrSocket};
use crate::security::parse_userspec;

#[expect(clippy::too_many_lines, reason = "WIP")]
fn build_clap_command() -> Command {
    // TODO: How do we return a specific error (e.g. 3 for the user spec's value parser) when an error occurs?

    command!()
        .disable_version_flag(true)
        .color(clap::ColorChoice::Always)
        .long_version(format!(
            "- Web Service Discovery Daemon, v{}",
            env!("CARGO_PKG_VERSION")
        ))
        .version(format!("v{}", env!("CARGO_PKG_VERSION")))
        .arg(
            Arg::new("interface")
                .long("interface")
                .short('i')
                .help("interface or address to use")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("hoplimit")
                .short('H')
                .long("hoplimit")
                .help("limit for multicast packets")
                .default_value("1")
                .value_parser(value_parser!(u8)),
        )
        .arg(
            Arg::new("uuid")
                .short('U')
                .long("uuid")
                .help("UUID for the target device")
                .value_parser(value_parser!(Uuid)),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("increase verbosity")
                .default_value("0")
                .action(ArgAction::Count),
        )
        .arg(
            Arg::new("domain")
                .short('d')
                .long("domain")
                .group("domain-workgroup")
                .help("set domain name (disables workgroup)"),
        )
        .arg(
            Arg::new("hostname")
                .short('n')
                .long("hostname")
                .help("override (NetBIOS) hostname to be used")
                .default_value("hostname"),
        )
        .arg(
            Arg::new("workgroup")
                .short('w')
                .long("workgroup")
                .group("domain-workgroup")
                .help("set workgroup name")
                .default_value("WORKGROUP"),
        )
        .arg(
            Arg::new("no-autostart")
                .short('A')
                .long("no-autostart")
                .help("do not start networking after launch")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-http")
                .short('t')
                .long("no-http")
                .help("disable http service (for debugging).arg( e.g.)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ipv4only")
                .short('4')
                .long("ipv4only")
                .group("ip")
                .help("use only IPv4")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ipv6only")
                .short('6')
                .long("ipv6only")
                .group("ip")
                .help("use only IPv6")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("shortlog")
                .short('s')
                .long("shortlog")
                .help("log only level and message")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("preserve-case")
                .short('p')
                .long("preserve-case")
                .help("preserve case of the provided/detected hostname")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("chroot")
                .short('c')
                .long("chroot")
                .help("directory to chroot into")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("user")
                .short('u')
                .long("user")
                .help("drop privileges to user:group")
                .value_parser(parse_userspec),
        )
        .arg(
            Arg::new("discovery")
                .short('D')
                .long("discovery")
                .help("enable discovery operation mode")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("listen")
                .short('l')
                .long("listen")
                .help("listen on path or localhost port in discovery mode")
                .value_parser(to_listen),
        )
        .arg(
            Arg::new("no-host")
                .short('o')
                .long("no-host")
                .help("disable server mode operation (host will be undiscoverable)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .help("show version number and exit")
                .action(ArgAction::Version),
        )
        .arg(
            Arg::new("metadata-timeout")
                .long("metadata-timeout")
                .help("set timeout for HTTP-based metadata exchange")
                .value_parser(float_to_duration_parser)
                .default_value("2.0"),
        )
        .arg(
            Arg::new("source-port")
                .long("source-port")
                .help("send multicast traffic/receive replies on this port")
                .value_parser(clap::value_parser!(u16))
                .default_value("0"),
        )
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
    let mut command = build_clap_command();
    let matches = command.try_get_matches_from_mut(from)?;

    let interfaces: Vec<String> = if let Some(interfaces) = matches.get_many::<String>("interface")
    {
        interfaces.cloned().collect::<Vec<_>>()
    } else {
        event!(Level::WARN, "no interface given, using all interfaces");

        vec![]
    };

    let hostname = if let Some(hostname) = get_user_cli_value::<String>(&matches, "hostname") {
        hostname.clone()
    } else {
        let hostname = gethostname()?;

        hostname
            .split_once('.')
            .map(|(first, _rest)| first.to_owned())
            .unwrap_or(hostname)
    };

    let verbosity = match get_user_cli_value::<u8>(&matches, "verbose") {
        None | Some(&0) => Level::WARN,
        Some(&1) => Level::INFO,
        Some(_) => Level::DEBUG,
    };

    let uuid = match get_user_cli_value::<Uuid>(&matches, "uuid") {
        Some(uuid) => Ok(*uuid),
        None => get_uuid_from_machine(),
    }?;

    let listen = matches.get_one::<PortOrSocket>("listen").cloned();

    let config = Config {
        interface: interfaces,
        hoplimit: *matches.get_one("hoplimit").expect("hoplimit has a default"),
        uuid,
        verbosity,
        domain: matches.get_one("domain").cloned(),
        hostname,
        workgroup: matches
            .get_one("workgroup")
            .cloned()
            .expect("workgroup has a default"),
        no_autostart: matches.get_one("no-autostart").copied().unwrap_or(false),
        no_http: matches.get_one("no-http").copied().unwrap_or(false),
        ipv4only: matches.get_one("ipv4only").copied().unwrap_or(false),
        ipv6only: matches.get_one("ipv6only").copied().unwrap_or(false),
        shortlog: matches.get_one("shortlog").copied().unwrap_or(false),
        preserve_case: matches.get_one("preserve-case").copied().unwrap_or(false),
        chroot: matches.get_one("chroot").cloned(),
        user: matches.get_one("user").copied(),
        discovery: matches.get_one("discovery").copied().unwrap_or(false),
        listen,
        no_host: matches.get_one("no-host").copied().unwrap_or(false),
        metadata_timeout: matches
            .get_one("metadata-timeout")
            .copied()
            .expect("metadata-timeout has a default"),
        source_port: matches
            .get_one("source-port")
            .copied()
            .expect("source-port has a default"),
        wsd_instance_id: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Before epoch? Time travel?")
            .as_secs()
            .to_string()
            .into(),
    };

    // TODO
    //     for prefix, uri in namespaces.items():
    //         ElementTree.register_namespace(prefix, uri)

    Ok(config)
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

fn gethostname() -> Result<String, eyre::Report> {
    let mut buffer = [0_u8; 255 /* POSIX LIMIT */ + 1 /* for the \0 */];

    // SAFETY: libc call
    let length = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };

    if length == -1 {
        return Err(Error::last_os_error().into());
    }

    let hostname = CStr::from_bytes_until_nul(&buffer)
        .expect("We used oversized buffer, so not finding a null is impossible")
        .to_str()?;

    Ok(String::from(hostname))
}

fn get_uuid_from_machine() -> Result<Uuid, eyre::Report> {
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

fn get_user_cli_value<'a, T>(matches: &'a clap::ArgMatches, key: &str) -> Option<&'a T>
where
    T: Clone + Send + Sync + 'static,
{
    // our CLI has defaults, so we check if the user has provided a value
    let Some(ValueSource::CommandLine) = matches.value_source(key) else {
        return None;
    };

    // NOTE: we might change this later to always use the user's input, as we might want this module
    // to drive the config's defaults.
    // I am always confused as to who should do what. Who provides defaults? Who provides upper and lower limits?
    // Because not everything comes through a CLI. I would love to share this with something like
    // a yaml file. But then we run into issues with valid values for a type (say 1 for max-line-length) but
    // that's an invalid number in our logic.
    // on the other hand there are port 100000 which doesn't even fit into our data type

    // return the value provided by the user
    matches.get_one::<T>(key)
}
