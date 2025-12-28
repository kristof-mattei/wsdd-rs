use thiserror::Error;
use url::Url;

pub struct XAddr {
    url: Url,
}

impl XAddr {
    pub fn get_url(&self) -> &Url {
        &self.url
    }
}

impl std::fmt::Display for XAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url.as_str())
    }
}

#[derive(Error, Debug)]
pub enum XAddrError {
    #[error("Error parsing raw xaddr as URL")]
    UrlParseError(#[from] url::ParseError),
    #[error("Error parsing URL as XAddr")]
    InvalidXAddrError,
}

impl<'s> TryFrom<&'s str> for XAddr {
    type Error = XAddrError;

    fn try_from(value: &'s str) -> Result<Self, Self::Error> {
        let url = Url::parse(value)?;

        // XAddrs must be HTTP or HTTPS addresses. XAddrs of other schemes are ignored.
        if let "http" | "https" = url.scheme()
            && url.has_host()
        {
            Ok(XAddr { url })
        } else {
            Err(XAddrError::InvalidXAddrError)
        }
    }
}

impl From<XAddr> for Url {
    fn from(value: XAddr) -> Self {
        value.url
    }
}
