mod address_monitor;
mod api_server;
mod cli;
mod config;
mod constants;
mod ffi;
mod ffi_wrapper;
mod helpers;
mod max_size_deque;
mod multicast_handler;
mod netlink_address_monitor;
mod network_address;
mod network_handler;
mod network_interface;
mod parsers;
mod security;
mod signal_handlers;
mod soap;
mod test_utils;
mod udp_address;
mod url_ip_addr;
mod utils;
mod wsd;
mod xml;

use std::env::{self, VarError};
use std::sync::Arc;
use std::time::Duration;

use color_eyre::config::HookBuilder;
use color_eyre::eyre;
use dotenvy::dotenv;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _};

use crate::cli::parse_cli;
use crate::network_handler::NetworkHandler;
use crate::security::{chroot, drop_privileges};
use crate::utils::flatten_handle;

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

fn main() -> Result<(), eyre::Report> {
    // set up .env, if it fails, user didn't provide any
    let _r = dotenv();

    HookBuilder::default()
        .capture_span_trace_by_default(true)
        .display_env_section(false)
        .install()?;

    let (env_filter, parsing_error) = build_filter();

    init_tracing(env_filter)?;

    // bubble up the parsing error
    parsing_error.map_or(Ok(()), Err)?;

    // initialize the runtime
    let result: Result<(), eyre::Report> = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Failed building the Runtime")
        .block_on(async {
            // explicitly launch everything in a spawned task
            // see https://docs.rs/tokio/latest/tokio/attr.main.html#non-worker-async-function
            let handle = tokio::task::spawn(start_tasks());

            flatten_handle(handle).await
        });

    result
}

fn print_header() {
    const NAME: &str = env!("CARGO_PKG_NAME");
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    event!(
        Level::INFO,
        "{} v{} - built for {}-{}",
        NAME,
        VERSION,
        std::env::var("TARGETARCH")
            .as_deref()
            .unwrap_or("unknown-arch"),
        std::env::var("TARGETVARIANT")
            .as_deref()
            .unwrap_or("base variant")
    );
}

#[expect(clippy::too_many_lines, reason = "WIP")]
async fn start_tasks() -> Result<(), eyre::Report> {
    let config = Arc::new(parse_cli().inspect_err(|error| {
        // this prints the error in color and exits
        // can't do anything else until
        // https://github.com/clap-rs/clap/issues/2914
        // is merged in
        if let Some(clap_error) = error.downcast_ref::<clap::error::Error>() {
            clap_error.exit();
        }
    })?);

    print_header();

    config.log();

    if let &Some(ref chroot_path) = &config.chroot {
        if let Err(error) = chroot(chroot_path) {
            event!(
                Level::ERROR,
                ?error,
                "could not chroot to {}",
                chroot_path.display()
            );

            // TODO error more gracefully
            #[expect(clippy::exit, reason = "Daemonize failed, all we can do is die")]
            std::process::exit(2);
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

        // TODO error more gracefully
        #[expect(clippy::exit, reason = "Daemonize failed, all we can do is die")]
        std::process::exit(3);
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

    // TODO
    // if args.ipv4only and args.ipv6only:
    //     logger.error('Listening to no IP address family.')
    //     return 4

    // this channel is used to communicate between
    // tasks and this function, in the case that a task fails, they'll send a message on the shutdown channel
    // after which we'll gracefully terminate other services
    let cancellation_token = CancellationToken::new();

    let tasks = tokio_util::task::TaskTracker::new();

    let (sender, receiver) = tokio::sync::mpsc::channel(10);

    let mut network_handler = NetworkHandler::new(cancellation_token.clone(), &config, receiver);
    network_handler.set_active();

    {
        let mut address_monitor =
            address_monitor::create_address_monitor(cancellation_token.clone(), sender, &config)?;

        address_monitor.request_current_state()?;

        let cancellation_token = cancellation_token.clone();

        tasks.spawn(async move {
            let _guard = cancellation_token.drop_guard();

            match address_monitor.handle_change().await {
                Ok(()) => event!(Level::INFO, "Address Monitor stopped listening"),
                Err(error) => {
                    event!(Level::ERROR, ?error, "TODO");
                },
            }
        });
    }

    {
        let cancellation_token = cancellation_token.clone();

        tasks.spawn(async move {
            let _guard = cancellation_token.drop_guard();

            match network_handler.handle_change().await {
                Ok(()) => event!(Level::INFO, "Network handler stopped listening"),
                Err(error) => {
                    event!(Level::ERROR, ?error, "TODO");
                },
            }

            network_handler.teardown().await;
        });
    }

    // TODO
    // api_server = None
    // let api_server = if let Some(listen) = config.listen {
    //     api_server = ApiServer(aio_loop, args.listen, nm)
    // ApiServer::new(listen, )
    // };

    // # main loop, serve requests coming from any outbound socket
    // try:
    //     aio_loop.run_forever()
    // except (SystemExit, KeyboardInterrupt):
    //     logger.info('shutting down gracefully...')
    //     if api_server is not None:
    //         aio_loop.run_until_complete(api_server.cleanup())

    //     nm.cleanup()
    //     aio_loop.stop()
    // except Exception:
    //     logger.exception('error in main loop')

    // logger.info('Done.')
    // return 0

    // now we wait forever for either
    // * SIGTERM
    // * ctrl + c (SIGINT)
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
                event!(Level::ERROR, ?error, "Failed to register CTRL+C handler, aborting");
            } else {
                // we completed because ...
                event!(Level::WARN, "CTRL+C detected, stopping all tasks");
            }
        },
        () = cancellation_token.cancelled() => {
            event!(Level::WARN, "Underlying task stopped, stopping all others tasks");
        },
    }

    // backup, in case we forgot a dropguard somewhere
    cancellation_token.cancel();

    tasks.close();

    // wait for the task that holds the server to exit gracefully
    // it listens to shutdown_send
    // TODO restore back to 10_000
    if timeout(Duration::from_millis(1_000_000), tasks.wait())
        .await
        .is_err()
    {
        event!(Level::ERROR, "Tasks didn't stop within allotted time!");
    }

    event!(Level::INFO, "Goodbye");

    Ok(())
}
