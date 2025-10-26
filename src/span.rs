use http::Request;
use tower_http::trace::MakeSpan;
use tracing::{Level, Span};
use uuid::Uuid;

// Copied from https://github.com/tower-rs/tower-http/blob/35740decc663f4921b85b234ae33580f40fcbb31/tower-http/src/trace/mod.rs#L472
const DEFAULT_MESSAGE_LEVEL: Level = Level::DEBUG;

/// Creates a [`Span`] like [`DefaultMakeSpan`], with an added `id` so that individual requests can be traced all the way
///
/// [`Span`]: tracing::Span
/// [`DefaultMakeSpan`]: tower_http::trace::DefaultMakeSpan
#[derive(Debug, Clone)]
pub struct MakeSpanWithUuid {
    level: Level,
    include_headers: bool,
}

impl MakeSpanWithUuid {
    /// Create a new `MakeSpanWithUuid`.
    pub fn new() -> Self {
        Self {
            level: DEFAULT_MESSAGE_LEVEL,
            include_headers: false,
        }
    }

    /// Set the [`Level`] used for the [tracing span].
    ///
    /// Defaults to [`Level::DEBUG`].
    ///
    /// [tracing span]: https://docs.rs/tracing/latest/tracing/#spans
    pub fn level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    /// Include request headers on the [`Span`].
    ///
    /// By default headers are not included.
    ///
    /// [`Span`]: tracing::Span
    #[expect(unused, reason = "Copied from library")]
    pub fn include_headers(mut self, include_headers: bool) -> Self {
        self.include_headers = include_headers;
        self
    }
}

impl Default for MakeSpanWithUuid {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> MakeSpan<B> for MakeSpanWithUuid {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        // This ugly macro is needed, unfortunately, because `tracing::span!`
        // required the level argument to be static. Meaning we can't just pass
        // `self.level`.
        macro_rules! make_span {
            ($level:expr) => {
                if self.include_headers {
                    tracing::span!(
                        $level,
                        "request",
                        id = %Uuid::now_v7(),
                        method = %request.method(),
                        uri = %request.uri(),
                        version = ?request.version(),
                        headers = ?request.headers(),
                    )
                } else {
                    tracing::span!(
                        $level,
                        "request",
                        id = %Uuid::now_v7(),
                        method = %request.method(),
                        uri = %request.uri(),
                        version = ?request.version(),
                    )
                }
            }
        }

        match self.level {
            Level::ERROR => make_span!(Level::ERROR),
            Level::WARN => make_span!(Level::WARN),
            Level::INFO => make_span!(Level::INFO),
            Level::DEBUG => make_span!(Level::DEBUG),
            Level::TRACE => make_span!(Level::TRACE),
        }
    }
}
