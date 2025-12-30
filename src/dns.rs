#![expect(unused, reason = "WIP")]
use std::net::SocketAddr;
use std::pin::Pin;

use hyper_util::client::legacy::connect::dns::{
    GaiResolver as HyperGaiResolver, Name as HyperName,
};
use tower_http::BoxError;
use tower_service::Service as _;

/// Alias for an `Iterator` trait object over `SocketAddr`.
pub type Addrs = Box<dyn Iterator<Item = SocketAddr> + Send>;

/// Alias for the `Future` type returned by a DNS resolver.
pub type Resolving = Pin<Box<dyn Future<Output = Result<Addrs, BoxError>> + Send>>;

pub struct GaiResolver {
    inner: HyperGaiResolver,
}

impl std::default::Default for GaiResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl GaiResolver {
    pub fn new() -> Self {
        Self {
            inner: HyperGaiResolver::new(),
        }
    }

    pub fn resolve(&self, name: HyperName) -> Resolving {
        let mut this = self.inner.clone();

        Box::pin(async move {
            this.call(name)
                .await
                .map(|addrs| Box::new(addrs) as Addrs)
                .map_err(|err| Box::new(err) as BoxError)
        })
    }
}
