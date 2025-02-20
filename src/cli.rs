use core::str;
use std::env;
use std::ffi::{CStr, OsString};
use std::fs::File;
use std::io::{Error, Read};
use std::path::{Path, PathBuf};

use clap::parser::ValueSource;
use clap::{Arg, ArgAction, Command, command, value_parser};
use color_eyre::eyre;
use tracing::{Level, event};
use uuid::Uuid;

use crate::config::{Config, PortOrSocket};
use crate::constants::WSDD_VERSION;
use crate::security::parse_userspec;

#[expect(clippy::too_many_lines)]
fn build_clap_matcher() -> Command {
    let mut command = command!()
        .disable_version_flag(true)
        .color(clap::ColorChoice::Always);

    // TODO: How do we return a specific error (e.g. 3 for the user spec's value parser) when an error occurs?

    // let hostname = gethostname();
    // let hostname_p1 = hostname
    //     .split_once('.')
    //     .map(|(l, _)| l)
    //     .unwrap_or(&hostname);

    let commands = [
        Arg::new("interface")
            .long("interface")
            .short('i')
            .help("interface or address to use")
            .action(ArgAction::Append),
        Arg::new("hoplimit")
            .short('H')
            .long("hoplimit")
            .help("limit for multicast packets")
            .default_value("1")
            .value_parser(value_parser!(u8)),
        Arg::new("uuid")
            .short('U')
            .long("uuid")
            .help("UUID for the target device")
            .value_parser(value_parser!(Uuid)),
        // Arg::new("verbose")
        //     .short('v')
        //     .long("verbose")
        //     .help("increase verbosity")
        //     .default_value("0")
        //     .action(ArgAction::Count),
        Arg::new("domain")
            .short('d')
            .long("domain")
            .group("domain-workgroup")
            .help("set domain name (disables workgroup)"),
        Arg::new("hostname")
            .short('n')
            .long("hostname")
            .help("override (NetBIOS) hostname to be used")
            .default_value("hostname"),
        Arg::new("workgroup")
            .short('w')
            .long("workgroup")
            .group("domain-workgroup")
            .help("set workgroup name")
            .default_value("WORKGROUP"),
        Arg::new("no-autostart")
            .short('A')
            .long("no-autostart")
            .help("do not start networking after launch")
            .action(ArgAction::SetTrue),
        Arg::new("no-http")
            .short('t')
            .long("no-http")
            .help("disable http service (for debugging, e.g.)")
            .action(ArgAction::SetTrue),
        Arg::new("ipv4only")
            .short('4')
            .long("ipv4only")
            .group("ip")
            .help("use only IPv4")
            .action(ArgAction::SetTrue),
        Arg::new("ipv6only")
            .short('6')
            .long("ipv6only")
            .group("ip")
            .help("use only IPv6")
            .action(ArgAction::SetTrue),
        // Arg::new("shortlog")
        //     .short('s')
        //     .long("shortlog")
        //     .help("log only level and message")
        //     .action(ArgAction::SetTrue),
        Arg::new("preserve-case")
            .short('p')
            .long("preserve-case")
            .help("preserve case of the provided/detected hostname")
            .action(ArgAction::SetTrue),
        Arg::new("chroot")
            .short('c')
            .long("chroot")
            .help("directory to chroot into")
            .value_parser(value_parser!(PathBuf)),
        Arg::new("user")
            .short('u')
            .long("user")
            .help("drop privileges to user:group")
            .value_parser(parse_userspec),
        Arg::new("discovery")
            .short('D')
            .long("discovery")
            .help("enable discovery operation mode")
            .action(ArgAction::SetTrue),
        Arg::new("listen")
            .short('l')
            .long("listen")
            .help("listen on path or localhost port in discovery mode")
            .value_parser(to_listen),
        Arg::new("no-host")
            .short('o')
            .long("no-host")
            .help("disable server mode operation (host will be undiscoverable)")
            .action(ArgAction::SetTrue),
        Arg::new("version")
            .short('V')
            .long("version")
            .help("show version number and exit")
            .action(ArgAction::SetTrue),
        Arg::new("metadata-timeout")
            .long("metadata-timeout")
            .help("set timeout for HTTP-based metadata exchange")
            .value_parser(clap::value_parser!(f32))
            .default_value("2.0"),
        Arg::new("source-port")
            .long("source-port")
            .help("send multicast traffic/receive replies on this port")
            .value_parser(clap::value_parser!(u16))
            .default_value("0"),
    ];

    for (order, argument) in commands.into_iter().enumerate() {
        command = command.arg(argument.display_order(order));
    }

    command
}

pub fn parse_cli() -> Result<Config, eyre::Error> {
    parse_cli_from(env::args_os())
}

fn parse_cli_from<I, T>(from: I) -> Result<Config, eyre::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut command = build_clap_matcher();
    let matches = command.try_get_matches_from_mut(from)?;

    // def parse_args() -> None:
    //     global args, logger

    //     parser = argparse.ArgumentParser()

    //     args = parser.parse_args(sys.argv[1:])

    // if args.version:
    // TODO use clap's built-in
    if let Some(ValueSource::CommandLine) = matches.value_source("version") {
        // print('wsdd - web service discovery daemon, v{}'.format(wsdd_version))
        println!("wsdd-rs - web service discovery daemon, v{}", WSDD_VERSION);
        // sys.exit(0)
        std::process::exit(0);
    }

    // let verbose = matches.get_count("verbose");

    // // if args.verbose == 1:
    // if verbose == 1 {
    //     // log_level = logging.INFO

    //     // elif args.verbose > 1:
    // } else if verbose > 1 {
    //     // log_level = logging.DEBUG
    //     // asyncio.get_event_loop().set_debug(True)
    //     // logging.getLogger("asyncio").setLevel(logging.DEBUG)
    //     // else:
    // } else {
    //     // log_level = logging.WARNING
    // }

    //     if args.shortlog:
    //         fmt = '%(levelname)s: %(message)s'
    //     else:
    //         fmt = '%(asctime)s:%(name)s %(levelname)s(pid %(process)d): %(message)s'

    //     logging.basicConfig(level=log_level, format=fmt)
    //     logger = logging.getLogger('wsdd')

    //     if not args.interface:
    let interfaces: Vec<String> = if let Some(interfaces) = matches.get_many::<String>("interface")
    {
        interfaces.cloned().collect::<Vec<_>>()
    } else {
        // logger.warning('no interface given, using all interfaces')
        event!(Level::WARN, "no interface given, using all interfaces");

        vec![]
    };

    let hostname = if let Some(hostname) = get_user_cli_value::<String>(&matches, "hostname") {
        hostname.clone()
    } else {
        let hostname = gethostname()?;

        hostname
            .rsplit_once('.')
            .map(|(_l, r)| r.to_string())
            .unwrap_or(hostname)
    };

    //     if not args.uuid:
    let uuid = match get_user_cli_value::<Uuid>(&matches, "uuid") {
        Some(uuid) => Ok(*uuid),
        None => get_uuid_from_machine(),
    }?;

    let listen = matches.get_one::<PortOrSocket>("listen").cloned();

    let config = Config {
        interface: interfaces,
        hoplimit: *matches.get_one("hoplimit").expect("hoplimit has a default"),
        uuid,
        // verbose,
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
        // shortlog: matches.get_one("shortlog").copied().unwrap_or(false),
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
            (listen.parse::<u16>()).map_err(|_| "number too large to fit in u16".to_string())?;

        Ok(PortOrSocket::Port(listen))
    } else {
        Ok(PortOrSocket::SocketPath(PathBuf::from(listen)))
    }
}

fn gethostname() -> Result<String, std::io::Error> {
    let mut buffer = [0u8; 255 /* POSIX LIMIT */ + 1 /* for the \n */];

    let length = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };

    if length == -1 {
        return Err(Error::last_os_error());
    };

    let hostname = CStr::from_bytes_until_nul(&buffer)
        .expect("We used oversized buffer, so not finding a null is impossible")
        .to_str()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    Ok(String::from(hostname))
}

fn get_uuid_from_machine() -> Result<Uuid, eyre::Report> {
    fn read_uuid_from_file(path: &Path) -> Option<uuid::Uuid> {
        let mut file = File::open(path).ok()?;

        let mut content = String::new();
        file.read_to_string(&mut content).ok()?;

        uuid::Uuid::try_parse(&content).ok()
    }

    // machine uuid: try machine-id file first but also check for hostid (FreeBSD)
    let uuid = match read_uuid_from_file(Path::new("/etc/machine-id"))
        .or_else(|| read_uuid_from_file(Path::new("/etc/hostid")))
    {
        Some(uuid) => uuid,
        None => uuid::Uuid::new_v5(&Uuid::NAMESPACE_DNS, gethostname()?.as_bytes()),
    };

    event!(Level::INFO, "using pre-defined UUID {}", uuid);

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
