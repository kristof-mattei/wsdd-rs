use std::net::SocketAddr;
use std::sync::Arc;

use hickory_resolver::TokioResolver;
use hickory_resolver::net::NetError;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Resolves the host names in `XAddrs`.
#[derive(Debug)]
pub(crate) enum NameResolution {
    /// `getaddrinfo(3)`, which reads the system configuration on every lookup.
    System,
    /// Resolves with the system configuration read at startup, which remains usable after `chroot(2)`.
    Snapshot(SnapshotResolver),
}

impl NameResolution {
    pub(crate) fn client_builder(&self) -> reqwest::ClientBuilder {
        let builder = reqwest::ClientBuilder::new();

        match *self {
            NameResolution::System => builder,
            NameResolution::Snapshot(ref resolver) => builder.dns_resolver(resolver.clone()),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SnapshotResolver {
    resolver: Arc<TokioResolver>,
}

impl SnapshotResolver {
    /// Reads `/etc/resolv.conf` and `/etc/hosts`.
    pub(crate) fn from_system() -> Result<Self, NetError> {
        let resolver = TokioResolver::builder_tokio()?.build()?;

        Ok(Self {
            resolver: Arc::new(resolver),
        })
    }
}

impl Resolve for SnapshotResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = Arc::clone(&self.resolver);

        Box::pin(async move {
            let lookup = resolver.lookup_ip(name.as_str()).await?;

            let addrs: Addrs = Box::new(
                lookup
                    .into_iter()
                    .map(|address| SocketAddr::new(address, 0)),
            );

            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use reqwest::dns::Resolve as _;

    use crate::name_resolution::SnapshotResolver;

    #[cfg_attr(miri, ignore = "reads `/etc/resolv.conf` and `/etc/hosts`")]
    #[tokio::test]
    async fn snapshot_resolves_localhost() {
        let resolver = SnapshotResolver::from_system().unwrap();

        let addrs = resolver
            .resolve("localhost".parse().unwrap())
            .await
            .unwrap()
            .collect::<Vec<_>>();

        assert!(
            !addrs.is_empty()
                && addrs
                    .iter()
                    .all(|addr| addr.ip().is_loopback() && addr.port() == 0),
            "{:?}",
            addrs
        );
    }
}
