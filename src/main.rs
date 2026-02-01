mod address_monitor;
mod api_server;
mod build_env;
mod cli;
mod config;
mod constants;
mod dns;
mod ffi;
mod helpers;
mod kernel_buffer;
mod max_size_deque;
mod multicast_handler;
mod netlink;
mod network_address;
mod network_handler;
mod network_interface;
mod parsers;
mod security;
mod shutdown;
mod signal_handlers;
mod soap;
mod socket;
mod span;
mod test_utils;
mod udp_address;
mod url_ip_addr;
mod utils;
mod wsd;
mod xml;

use std::convert::Infallible;
use std::env::{self, VarError};
use std::process::{ExitCode, Termination as _};
use std::sync::Arc;
use std::time::Duration;

use color_eyre::config::HookBuilder;
use color_eyre::eyre;
use dotenvy::dotenv;
use tokio::sync::mpsc::Sender;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _};

use crate::address_monitor::create_address_monitor;
use crate::build_env::get_build_env;
use crate::cli::parse_cli;
use crate::config::{Config, PortOrSocket};
use crate::network_handler::{Command, NetworkHandler};
use crate::security::{chroot, drop_privileges};
use crate::shutdown::Shutdown;
use crate::utils::flatten_shutdown_handle;

#[cfg_attr(not(miri), global_allocator)]
#[cfg_attr(miri, expect(unused, reason = "Not supported in Miri"))]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn build_filter() -> (EnvFilter, Option<eyre::Report>) {
    fn build_default_filter() -> EnvFilter {
        EnvFilter::builder()
            .parse(format!("INFO,{}=TRACE", env!("CARGO_CRATE_NAME")))
            .expect("Default filter should always work")
    }

    let (filter, parsing_error) = match env::var(EnvFilter::DEFAULT_ENV) {
        Ok(user_directive) => match EnvFilter::builder().parse(user_directive) {
            Ok(filter) => (filter, None),
            Err(error) => (build_default_filter(), Some(eyre::Report::new(error))),
        },
        Err(VarError::NotPresent) => (build_default_filter(), None),
        Err(error @ VarError::NotUnicode(_)) => {
            (build_default_filter(), Some(eyre::Report::new(error)))
        },
    };

    (filter, parsing_error)
}

fn init_tracing(filter: EnvFilter) -> Result<(), eyre::Report> {
    let registry = tracing_subscriber::registry();

    #[cfg(feature = "tokio-console")]
    let registry = registry.with(console_subscriber::ConsoleLayer::builder().spawn());

    Ok(registry
        .with(tracing_subscriber::fmt::layer().with_filter(filter))
        .with(tracing_error::ErrorLayer::default())
        .try_init()?)
}

fn main() -> ExitCode {
    // set up .env, if it fails, user didn't provide any
    let _r = dotenv();

    HookBuilder::default()
        .capture_span_trace_by_default(true)
        .display_env_section(false)
        .install()
        .expect("Failed to install panic handler");

    let (env_filter, parsing_error) = build_filter();

    init_tracing(env_filter).expect("Failed to set up tracing");

    // bubble up the parsing error
    if let Err(error) = parsing_error.map_or(Ok(()), Err) {
        return Err::<Infallible, _>(error).report();
    }

    // initialize the runtime
    let shutdown: Shutdown = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Failed building the Runtime")
        .block_on(async {
            // explicitly launch everything in a spawned task
            // see https://docs.rs/tokio/latest/tokio/attr.main.html#non-worker-async-function
            let handle = tokio::task::spawn(start_tasks());

            flatten_shutdown_handle(handle).await
        });

    shutdown.report()
}

fn print_header() {
    const NAME: &str = env!("CARGO_PKG_NAME");
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    let build_env = get_build_env();

    event!(
        Level::INFO,
        "{} v{} - built for {} ({})",
        NAME,
        VERSION,
        build_env.get_target(),
        build_env.get_target_cpu().unwrap_or("base cpu variant"),
    );
}

fn get_config() -> Result<Arc<Config>, eyre::Report> {
    let config = Arc::new(parse_cli().inspect_err(|error| {
        // this prints the error in color and exits
        // can't do anything else until
        // https://github.com/clap-rs/clap/issues/2914
        // is merged in
        if let Some(clap_error) = error.downcast_ref::<clap::error::Error>() {
            clap_error.exit();
        }
    })?);

    Ok(config)
}

fn try_chroot(config: &Config) -> Option<Shutdown> {
    if let &Some(ref chroot_path) = &config.chroot {
        if let Err(error) = chroot(chroot_path) {
            event!(
                Level::ERROR,
                ?error,
                "could not chroot to {}",
                chroot_path.display()
            );

            return Some(Shutdown::OperationalFailure {
                code: ExitCode::from(2),
                message: "chroot failed",
            });
        } else {
            event!(
                Level::INFO,
                "chrooted successfully to {}",
                chroot_path.display()
            );
        }
    }

    if let &Some((uid, gid)) = &config.user
        && let Err(reason) = drop_privileges(uid, gid)
    {
        event!(Level::ERROR, ?uid, ?gid, reason, "Drop privileges failed");

        return Some(Shutdown::OperationalFailure {
            code: ExitCode::from(3),
            message: "drop privileges failed",
        });
    }

    if config.chroot.is_some()
        &&
        // SAFETY: libc call
        (unsafe { libc::getuid() == 0 } ||
            // SAFETY: libc call
            unsafe { libc::getgid() == 0 })
    {
        event!(
            Level::WARN,
            "chrooted but running as root, consider -u option"
        );
    }

    None
}

/// starts all the tasks, such as the web server, the key refresh, ...
/// ensures all tasks are gracefully shutdown in case of error, `CTRL+c` or `SIGTERM`.
async fn start_tasks() -> Shutdown {
    let config = match get_config() {
        Ok(config) => config,
        Err(error) => return Shutdown::from(error),
    };

    print_header();

    config.log();

    if let Some(shutdown) = try_chroot(&config) {
        return shutdown;
    }

    // this channel is used to communicate between
    // tasks and this function, in the case that a task fails, they'll send a message on the shutdown channel
    // after which we'll gracefully terminate other services
    let cancellation_token = CancellationToken::new();

    let tasks = tokio_util::task::TaskTracker::new();

    let (command_tx, command_rx) = tokio::sync::mpsc::channel(10);
    let (start_tx, start_rx) = tokio::sync::watch::channel::<()>(());

    let mut network_handler =
        NetworkHandler::new(cancellation_token.clone(), &config, command_rx, start_tx);

    {
        let cancellation_token = cancellation_token.clone();
        let config = Arc::clone(&config);
        let command_tx = command_tx.clone();

        tasks.spawn(launch_address_monitor(
            cancellation_token,
            command_tx,
            start_rx,
            config,
        ));
    }

    if !config.no_autostart {
        if let Err(error) = network_handler.set_active() {
            return error.into();
        }
    }

    {
        let cancellation_token = cancellation_token.clone();

        tasks.spawn(launch_network_handler_task(
            cancellation_token,
            network_handler,
        ));
    }

    if let Some(listen_on) = config.listen.clone() {
        let cancellation_token = cancellation_token.clone();
        let command_tx = command_tx.clone();

        tasks.spawn(launch_api_server(cancellation_token, command_tx, listen_on));
    }

    // now we wait forever for either
    // * SIGTERM
    // * CTRL+c (SIGINT)
    // * a message on the shutdown channel, sent either by the server task or
    // another task when they complete (which means they failed)
    tokio::select! {
        result = signal_handlers::wait_for_sigterm() => {
            if let Err(error) = result {
                event!(Level::ERROR, ?error, "Failed to register SIGERM handler, aborting");
            } else {
                // we completed because ...
                event!(Level::WARN, "Sigterm detected, stopping all tasks");
            }
        },
        result = signal_handlers::wait_for_sigint() => {
            if let Err(error) = result {
                event!(Level::ERROR, ?error, "Failed to register CTRL+c handler, aborting");
            } else {
                // we completed because ...
                event!(Level::WARN, "CTRL+c detected, stopping all tasks");
            }
        },
        () = cancellation_token.cancelled() => {
            event!(Level::WARN, "Underlying task stopped, stopping all others tasks");
        },
    }

    // backup, in case we forgot a dropguard somewhere
    cancellation_token.cancel();

    tasks.close();

    if timeout(Duration::from_secs(10), tasks.wait())
        .await
        .is_err()
    {
        event!(Level::ERROR, "Tasks didn't stop within allotted time!");
    }

    event!(Level::INFO, "Done");

    Shutdown::Success
}

async fn launch_address_monitor(
    cancellation_token: CancellationToken,
    command_tx: Sender<Command>,
    start_rx: tokio::sync::watch::Receiver<()>,
    config: Arc<Config>,
) {
    let _guard = cancellation_token.clone().drop_guard();

    let address_monitor = match create_address_monitor(
        cancellation_token.child_token(),
        command_tx,
        start_rx,
        Arc::clone(&config),
    ) {
        Ok(address_monitor) => address_monitor,
        Err(error) => {
            event!(Level::ERROR, ?error, "Failed to create address monitor");
            return;
        },
    };

    match address_monitor.process_changes().await {
        Ok(()) => event!(Level::INFO, "Address Monitor stopped listening"),
        Err(error) => {
            event!(Level::ERROR, ?error, "Address Monitor stopped unexpectedly");
        },
    }

    address_monitor.teardown().await;
}

async fn launch_api_server(
    cancellation_token: CancellationToken,
    command_tx: Sender<Command>,
    listen_on: PortOrSocket,
) {
    let _guard = cancellation_token.clone().drop_guard();

    let api_server = match api_server::ApiServer::new(
        cancellation_token.child_token(),
        &listen_on,
        command_tx,
    ) {
        Ok(api_server) => api_server,
        Err(error) => {
            event!(Level::ERROR, ?error, "Failed to start API Server");
            return;
        },
    };

    match api_server.handle_connections().await {
        Ok(()) => event!(Level::INFO, "API Server stopped listening"),
        Err(error) => {
            event!(Level::ERROR, ?error, "API Server stopped unexpectedly");
        },
    }

    api_server.teardown();
}

async fn launch_network_handler_task(
    cancellation_token: CancellationToken,
    mut network_handler: NetworkHandler,
) {
    let _guard = cancellation_token.drop_guard();

    match network_handler.process_commands().await {
        Ok(()) => event!(Level::INFO, "Network Handler stopped listening"),
        Err(error) => {
            event!(Level::ERROR, ?error, "Network Handler stopped unexpectedly");
        },
    }

    network_handler.teardown().await;
}
