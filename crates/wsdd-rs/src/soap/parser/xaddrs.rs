use thiserror::Error;
use url::Url;

pub struct XAddr {
    url: Url,
}

impl XAddr {
    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn host_str(&self) -> &str {
        self.url
            .host_str()
            .expect("XAddrs cannot be constructed from URLs that don't have a host")
    }
}

impl std::fmt::Display for XAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url.as_str())
    }
}

#[derive(Error, Debug)]
pub enum XAddrError<'s> {
    #[error("Failed to parse XAddr as URL: {0}")]
    UrlParseError(#[from] url::ParseError),
    #[error("XAddr must be an HTTP/HTTPS URL with a host: {0}")]
    InvalidXAddrError(&'s str),
}

impl<'s> TryFrom<&'s str> for XAddr {
    type Error = XAddrError<'s>;

    fn try_from(value: &'s str) -> Result<Self, Self::Error> {
        let url = Url::parse(value)?;

        // XAddrs must be HTTP or HTTPS addresses. XAddrs of other schemes are ignored.
        if let "http" | "https" = url.scheme()
            && url.has_host()
        {
            Ok(XAddr { url })
        } else {
            Err(XAddrError::InvalidXAddrError(value))
        }
    }
}

impl From<XAddr> for Url {
    fn from(value: XAddr) -> Self {
        value.url
    }
}
