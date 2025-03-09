#![allow(clippy::needless_lifetimes)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::unused_self)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::too_many_lines)]
mod address_monitor;
mod api_server;
mod cli;
mod config;
mod constants;
mod ffi;
mod ffi_wrapper;
mod helpers;
mod multicast_handler;
mod netlink_address_monitor;
mod network_address;
mod network_handler;
mod network_interface;
mod network_packet_handler;
mod parsers;
mod security;
mod signal_handlers;
mod soap;
mod udp_address;
mod url_ip_addr;
mod utils;
mod wsd;

use std::env;
use std::sync::Arc;
use std::time::Duration;

use color_eyre::eyre;
use dotenvy::dotenv;
use network_handler::NetworkHandler;
use security::{chroot, drop_privileges};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::cli::parse_cli;

fn init_tracing(console_subscriber: bool) -> Result<(), eyre::Report> {
    let main_filter = EnvFilter::builder()
        .parse(env::var(EnvFilter::DEFAULT_ENV).unwrap_or_else(|_| {
            format!("INFO,{}=DEBUG", env!("CARGO_PKG_NAME").replace('-', "_"))
        }))?;

    let registry = tracing_subscriber::registry()
        .with(console_subscriber.then(|| {
            console_subscriber::ConsoleLayer::builder()
                .with_default_env()
                .spawn()
        }))
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .and_then(tracing_error::ErrorLayer::default())
                .with_filter(main_filter),
        );

    tracing::subscriber::set_global_default(registry).expect("Unable to set global subscriber");

    Ok(())
}

fn main() -> Result<(), eyre::Report> {
    // set up .env, if it fails, user didn't provide any
    let _r = dotenv();

    color_eyre::config::HookBuilder::default()
        .capture_span_trace_by_default(false)
        .install()?;

    // TODO this param should come from env / config,
    init_tracing(true)?;

    // initialize the runtime
    let rt = tokio::runtime::Runtime::new().unwrap();

    // start service
    let result: Result<(), eyre::Report> = rt.block_on(start_tasks());

    result
}

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

    config.log();

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
                Ok(()) => (),
                Err(error) => event!(Level::ERROR, ?error, "TODO"),
            }
        });
    }

    {
        let cancellation_token = cancellation_token.clone();

        tasks.spawn(async move {
            let _guard = cancellation_token.drop_guard();

            match network_handler.handle_change().await {
                Ok(()) => (),
                Err(error) => {
                    event!(Level::ERROR, ?error, "TODO");
                },
            }
        });
    }

    // TODO
    // api_server = None
    // let api_server = if let Some(listen) = config.listen {
    //     api_server = ApiServer(aio_loop, args.listen, nm)
    // ApiServer::new(listen, )
    // };
    if let Some(chroot_path) = &config.chroot {
        if let Err(err) = chroot(chroot_path) {
            event!(
                Level::ERROR,
                ?err,
                "could not chroot to {}",
                chroot_path.display()
            );

            // TODO error more gracefully
            std::process::exit(2);
        } else {
            event!(
                Level::INFO,
                "chrooted successfully to {}",
                chroot_path.display()
            );
        }
    }

    if let &Some((uid, gid)) = &config.user {
        if let Err(reason) = drop_privileges(uid, gid) {
            event!(Level::ERROR, ?uid, ?gid, reason, "Drop privileges failed");

            // TODO error more gracefully
            std::process::exit(3);
        };
    }

    if config.chroot.is_some() && (unsafe { libc::getuid() == 0 || libc::getgid() == 0 }) {
        event!(
            Level::WARN,
            "chrooted but running as root, consider -u option"
        );
    }

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
        _ = signal_handlers::wait_for_sigint() => {
            // we completed because ...
            event!(Level::WARN, message = "CTRL+C detected, stopping all tasks");
        },
        _ = signal_handlers::wait_for_sigterm() => {
            // we completed because ...
            event!(Level::WARN, message = "Sigterm detected, stopping all tasks");
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
    if timeout(Duration::from_millis(10000), tasks.wait())
        .await
        .is_err()
    {
        event!(Level::ERROR, "Tasks didn't stop within allotted time!");
    }

    event!(Level::INFO, "Goodbye");

    Ok(())
}
