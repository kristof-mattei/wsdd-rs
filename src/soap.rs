use axum::response::IntoResponse;

use crate::soap::parser::bye::Bye;
use crate::soap::parser::get::Get;
use crate::soap::parser::hello::Hello;
use crate::soap::parser::probe::Probe;
use crate::soap::parser::probe_match::ProbeMatch;
use crate::soap::parser::resolve::Resolve;
use crate::soap::parser::resolve_match::ResolveMatch;

pub mod builder;
pub mod parser;

pub trait MessageType {
    fn message_type(&self) -> &str;
}

#[derive(Debug)]
pub enum UnicastMessage {
    GetResponse(Box<[u8]>),
    ProbeMatches(Box<[u8]>),
    ResolveMatches(Box<[u8]>),
}

impl AsRef<[u8]> for UnicastMessage {
    fn as_ref(&self) -> &[u8] {
        match *self {
            UnicastMessage::GetResponse(ref buffer)
            | UnicastMessage::ProbeMatches(ref buffer)
            | UnicastMessage::ResolveMatches(ref buffer) => buffer,
        }
    }
}

impl MessageType for UnicastMessage {
    fn message_type(&self) -> &str {
        match *self {
            UnicastMessage::GetResponse(_) => "GetResponse",
            UnicastMessage::ProbeMatches(_) => "ProbeMatches",
            UnicastMessage::ResolveMatches(_) => "ResolveMatches",
        }
    }
}

impl IntoResponse for UnicastMessage {
    fn into_response(self) -> axum::response::Response {
        match self {
            UnicastMessage::GetResponse(buffer)
            | UnicastMessage::ProbeMatches(buffer)
            | UnicastMessage::ResolveMatches(buffer) => buffer.into_response(),
        }
    }
}

#[derive(Debug)]
pub enum MulticastMessage {
    Hello(Box<[u8]>),
    Bye(Box<[u8]>),
    Probe(Box<[u8]>),
    Resolve(Box<[u8]>),
}
impl AsRef<[u8]> for MulticastMessage {
    fn as_ref(&self) -> &[u8] {
        match *self {
            MulticastMessage::Hello(ref buffer)
            | MulticastMessage::Bye(ref buffer)
            | MulticastMessage::Probe(ref buffer)
            | MulticastMessage::Resolve(ref buffer) => buffer,
        }
    }
}

impl MessageType for MulticastMessage {
    fn message_type(&self) -> &str {
        match *self {
            MulticastMessage::Hello(_) => "Hello",
            MulticastMessage::Bye(_) => "Bye",
            MulticastMessage::Probe(_) => "Probe",
            MulticastMessage::Resolve(_) => "Resolve",
        }
    }
}

pub enum ClientMessage {
    Hello(Hello),
    Bye(Bye),
    ProbeMatch(ProbeMatch),
    ResolveMatch(ResolveMatch),
}

impl From<ClientMessage> for WSDMessage {
    fn from(value: ClientMessage) -> Self {
        WSDMessage::ClientMessage(value)
    }
}

pub enum HostMessage {
    Get(Get),
    Probe(Probe),
    Resolve(Resolve),
}

impl From<HostMessage> for WSDMessage {
    fn from(value: HostMessage) -> Self {
        WSDMessage::HostMessage(value)
    }
}

pub enum WSDMessage {
    ClientMessage(ClientMessage),
    HostMessage(HostMessage),
}

impl From<Hello> for ClientMessage {
    fn from(value: Hello) -> Self {
        ClientMessage::Hello(value)
    }
}

impl From<Hello> for WSDMessage {
    fn from(value: Hello) -> Self {
        ClientMessage::Hello(value).into()
    }
}

impl From<Bye> for ClientMessage {
    fn from(value: Bye) -> Self {
        ClientMessage::Bye(value)
    }
}

impl From<Bye> for WSDMessage {
    fn from(value: Bye) -> Self {
        ClientMessage::Bye(value).into()
    }
}

impl From<Get> for HostMessage {
    fn from(value: Get) -> Self {
        HostMessage::Get(value)
    }
}

impl From<Get> for WSDMessage {
    fn from(value: Get) -> Self {
        HostMessage::Get(value).into()
    }
}

impl From<Probe> for HostMessage {
    fn from(value: Probe) -> Self {
        HostMessage::Probe(value)
    }
}

impl From<Probe> for WSDMessage {
    fn from(value: Probe) -> Self {
        HostMessage::Probe(value).into()
    }
}

impl From<Resolve> for HostMessage {
    fn from(value: Resolve) -> Self {
        HostMessage::Resolve(value)
    }
}

impl From<Resolve> for WSDMessage {
    fn from(value: Resolve) -> Self {
        HostMessage::Resolve(value).into()
    }
}

impl From<ProbeMatch> for ClientMessage {
    fn from(value: ProbeMatch) -> Self {
        ClientMessage::ProbeMatch(value)
    }
}

impl From<ProbeMatch> for WSDMessage {
    fn from(value: ProbeMatch) -> Self {
        ClientMessage::ProbeMatch(value).into()
    }
}

impl From<ResolveMatch> for ClientMessage {
    fn from(value: ResolveMatch) -> Self {
        ClientMessage::ResolveMatch(value)
    }
}

impl From<ResolveMatch> for WSDMessage {
    fn from(value: ResolveMatch) -> Self {
        ClientMessage::ResolveMatch(value).into()
    }
}

#[cfg_attr(not(test), expect(unused, reason = "Only used in tests"))]
impl WSDMessage {
    #[expect(unused, reason = "WIP")]
    pub fn into_get(self) -> Option<Get> {
        let WSDMessage::HostMessage(HostMessage::Get(get)) = self else {
            return None;
        };

        Some(get)
    }

    pub fn into_hello(self) -> Option<Hello> {
        let WSDMessage::ClientMessage(ClientMessage::Hello(hello)) = self else {
            return None;
        };

        Some(hello)
    }

    pub fn into_bye(self) -> Option<Bye> {
        let WSDMessage::ClientMessage(ClientMessage::Bye(bye)) = self else {
            return None;
        };

        Some(bye)
    }

    pub fn into_probe(self) -> Option<Probe> {
        let WSDMessage::HostMessage(HostMessage::Probe(probe)) = self else {
            return None;
        };

        Some(probe)
    }

    pub fn into_resolve(self) -> Option<Resolve> {
        let WSDMessage::HostMessage(HostMessage::Resolve(resolve)) = self else {
            return None;
        };

        Some(resolve)
    }

    pub fn into_probe_match(self) -> Option<ProbeMatch> {
        let WSDMessage::ClientMessage(ClientMessage::ProbeMatch(probe_match)) = self else {
            return None;
        };

        Some(probe_match)
    }

    pub fn into_resolve_match(self) -> Option<ResolveMatch> {
        let WSDMessage::ClientMessage(ClientMessage::ResolveMatch(resolve_match)) = self else {
            return None;
        };

        Some(resolve_match)
    }
}
