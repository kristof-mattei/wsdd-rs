use crate::constants;

/// The `wsa:Action` of a received message, see documentation/ws-addressing.pdf, 3.
pub(crate) enum Action {
    Hello,
    Bye,
    Probe,
    ProbeMatches,
    Resolve,
    ResolveMatches,
    Get,
    /// An action without a handler.
    Unsupported(Box<str>),
}

impl Action {
    /// The action URI.
    pub(crate) fn as_str(&self) -> &str {
        match *self {
            Action::Hello => constants::WSD_HELLO,
            Action::Bye => constants::WSD_BYE,
            Action::Probe => constants::WSD_PROBE,
            Action::ProbeMatches => constants::WSD_PROBE_MATCH,
            Action::Resolve => constants::WSD_RESOLVE,
            Action::ResolveMatches => constants::WSD_RESOLVE_MATCH,
            Action::Get => constants::WSD_GET,
            Action::Unsupported(ref action) => action,
        }
    }

    /// The last segment of the action URI.
    /// Returns `None` for an unsupported action without `/`.
    pub(crate) fn name(&self) -> Option<&str> {
        match *self {
            Action::Hello => Some(constants::WSD_HELLO_NAME),
            Action::Bye => Some(constants::WSD_BYE_NAME),
            Action::Probe => Some(constants::WSD_PROBE_NAME),
            Action::ProbeMatches => Some(constants::WSD_PROBE_MATCH_NAME),
            Action::Resolve => Some(constants::WSD_RESOLVE_NAME),
            Action::ResolveMatches => Some(constants::WSD_RESOLVE_MATCH_NAME),
            Action::Get => Some(constants::WSD_GET_NAME),
            Action::Unsupported(ref action) => action.rsplit_once('/').map(|(_, name)| name),
        }
    }
}

impl From<Box<str>> for Action {
    fn from(action: Box<str>) -> Self {
        match &*action {
            constants::WSD_HELLO => Action::Hello,
            constants::WSD_BYE => Action::Bye,
            constants::WSD_PROBE => Action::Probe,
            constants::WSD_PROBE_MATCH => Action::ProbeMatches,
            constants::WSD_RESOLVE => Action::Resolve,
            constants::WSD_RESOLVE_MATCH => Action::ResolveMatches,
            constants::WSD_GET => Action::Get,
            _ => Action::Unsupported(action),
        }
    }
}
