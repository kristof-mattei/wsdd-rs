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
mod message_receiver;
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
mod task_tracker_ext;
mod test_utils;
mod udp_address;
mod udp_socket_with_addr;
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
use color_eyre::eyre::{self, Context as _};
use dotenvy::dotenv;
use futures_util::future::{BoxFuture, FutureExt as _};
use futures_util::stream::{FuturesUnordered, StreamExt as _};
use tokio::sync::RwLock;
use tokio::sync::mpsc::Sender;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _};

use crate::address_monitor::create_address_monitor;
use crate::build_env::get_build_env;
use crate::cli::{CliArgs, parse_args, to_config};
use crate::config::{Config, PortOrSocket};
use crate::constants::WSD_MAX_KNOWN_MESSAGES;
use crate::max_size_deque::MaxSizeDeque;
use crate::network_handler::{Command, NetworkHandler};
use crate::security::{chroot, drop_privileges};
use crate::shutdown::Shutdown;
use crate::soap::MessageId;
use crate::utils::task::{flatten_shutdown_handle, spawn_with_name};

#[cfg_attr(not(miri), global_allocator)]
#[cfg_attr(miri, expect(unused, reason = "Not supported in Miri"))]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn build_filter() -> (EnvFilter, Option<eyre::Report>) {
    fn build_default_filter() -> EnvFilter {
        EnvFilter::builder()
            .parse(format!("INFO,{}=TRACE", env!("CARGO_CRATE_NAME")))
            .expect("Default filter should always work")
    }

    match env::var(EnvFilter::DEFAULT_ENV).as_deref().map(str::trim) {
        Ok("") | Err(&VarError::NotPresent) => (build_default_filter(), None),
        Ok(user_directive) => match EnvFilter::builder().parse(user_directive) {
            Ok(filter) => (filter, None),
            Err(error) => (build_default_filter(), Some(eyre::Report::new(error))),
        },
        Err(error @ &VarError::NotUnicode(_)) => (
            build_default_filter(),
            Some(eyre::Report::new(error.clone())),
        ),
    }
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

    // parse before tracing is set up, so `--help`/`--version` and usage errors
    // are not preceded by log output
    let args = match parse_args() {
        Ok(args) => args,
        Err(error) => {
            // this prints the error in color and exits
            // can't do anything else until
            // https://github.com/clap-rs/clap/issues/2914
            // is merged in
            if let Some(clap_error) = error.downcast_ref::<clap::error::Error>() {
                clap_error.exit();
            }

            return Err::<Infallible, _>(error).report();
        },
    };

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
            let handle = spawn_with_name("main task runner", start_tasks(args));

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
async fn start_tasks(args: CliArgs) -> Shutdown {
    print_header();

    let config = match to_config(args) {
        Ok(config) => Arc::new(config),
        Err(error) => return Shutdown::from(error),
    };

    config.log();

    if let Some(shutdown) = try_chroot(&config) {
        return shutdown;
    }

    let recent_messages: Arc<RwLock<MaxSizeDeque<MessageId>>> =
        Arc::new(RwLock::new(MaxSizeDeque::new(WSD_MAX_KNOWN_MESSAGES)));

    let cancellation_token = CancellationToken::new();

    let mut tasks = FuturesUnordered::new();

    let (command_tx, command_rx) = tokio::sync::mpsc::channel(10);
    let (start_tx, start_rx) = tokio::sync::watch::channel::<()>(());

    let mut network_handler = NetworkHandler::new(
        cancellation_token.clone(),
        &config,
        command_rx,
        start_tx,
        recent_messages,
    );

    tasks.push(spawn_task(
        "address monitor",
        launch_address_monitor(
            cancellation_token.child_token(),
            command_tx.clone(),
            start_rx,
            Arc::clone(&config),
        ),
    ));

    if !config.no_autostart {
        if let Err(error) = network_handler.set_active() {
            return error.into();
        }
    }

    tasks.push(spawn_task(
        "network handler",
        launch_network_handler(network_handler),
    ));

    if let Some(listen_on) = config.listen.clone() {
        tasks.push(spawn_task(
            "api server",
            launch_api_server(
                cancellation_token.child_token(),
                command_tx.clone(),
                listen_on,
            ),
        ));
    }

    // biased so that when multiple are ready at once, task failure wins over signals
    let shutdown_reason = tokio::select! {
        biased;
        Some((name, result)) = tasks.next() => {
            task_stopped(name, result)
        },
        result = signal_handlers::wait_for_sigterm() => {
            result
        },
        result = signal_handlers::wait_for_sigint() => {
            result
        },
    };

    cancellation_token.cancel();

    let drained = timeout(Duration::from_secs(10), async {
        while let Some((name, result)) = tasks.next().await {
            if let Err(report) = result {
                event!(
                    Level::ERROR,
                    task = name,
                    ?report,
                    "Task failed during the shutdown"
                );
            }
        }
    })
    .await
    .is_ok();

    if !drained {
        event!(Level::ERROR, "Tasks didn't stop within allotted time!");
    }

    // a shutdown that already reports a failure is returned unchanged
    if !drained && matches!(shutdown_reason, Shutdown::Success | Shutdown::Signal(_)) {
        return Shutdown::OperationalFailure {
            code: ExitCode::FAILURE,
            message: "Tasks didn't stop within the allotted time",
        };
    }

    event!(Level::INFO, "Shutdown completed");

    shutdown_reason
}

async fn launch_address_monitor(
    cancellation_token: CancellationToken,
    command_tx: Sender<Command>,
    start_rx: tokio::sync::watch::Receiver<()>,
    config: Arc<Config>,
) -> Result<(), eyre::Report> {
    let address_monitor = create_address_monitor(cancellation_token, command_tx, start_rx, config)
        .wrap_err("Failed to create address monitor")?;

    let result = address_monitor.process_changes().await;

    address_monitor.teardown().await;

    result
}

async fn launch_api_server(
    cancellation_token: CancellationToken,
    command_tx: Sender<Command>,
    listen_on: PortOrSocket,
) -> Result<(), eyre::Report> {
    let api_server = api_server::ApiServer::new(cancellation_token, &listen_on, command_tx)
        .wrap_err("Failed to start API Server")?;

    let result = api_server.handle_connections().await;

    api_server.teardown();

    result
}

async fn launch_network_handler(mut network_handler: NetworkHandler) -> Result<(), eyre::Report> {
    let result = network_handler.process_commands().await;

    network_handler.teardown().await;

    result
}

type TaskResult = Result<(), eyre::Report>;

fn spawn_task<F>(name: &'static str, task: F) -> BoxFuture<'static, (&'static str, TaskResult)>
where
    F: Future<Output = TaskResult> + Send + 'static,
{
    let handle = spawn_with_name(name, task);

    async move {
        let result = match handle.await {
            Ok(result) => result,
            Err(join_error) => Err(eyre::Report::new(join_error)),
        };

        (name, result)
    }
    .boxed()
}

/// Every task runs until the shutdown, so one that stops before it is a failure.
fn task_stopped(name: &'static str, result: TaskResult) -> Shutdown {
    match result {
        Ok(()) => {
            Shutdown::UnexpectedError(eyre::eyre!("Task `{}` stopped before the shutdown", name))
        },
        Err(report) => {
            Shutdown::UnexpectedError(report.wrap_err(format!("Task `{}` failed", name)))
        },
    }
}
