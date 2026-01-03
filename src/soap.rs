pub mod builder;
pub mod parser;

#[derive(Debug)]
pub enum UnicastMessage {
    ProbeMatches(Box<[u8]>),
    ResolveMatches(Box<[u8]>),
}

impl AsRef<[u8]> for UnicastMessage {
    fn as_ref(&self) -> &[u8] {
        match *self {
            UnicastMessage::ProbeMatches(ref buffer)
            | UnicastMessage::ResolveMatches(ref buffer) => buffer,
        }
    }
}

impl std::fmt::Display for UnicastMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            UnicastMessage::ProbeMatches(_) => write!(f, "ProbeMatches"),
            UnicastMessage::ResolveMatches(_) => write!(f, "ResolveMatches"),
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

impl std::fmt::Display for MulticastMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            MulticastMessage::Hello(_) => write!(f, "Hello"),
            MulticastMessage::Bye(_) => write!(f, "Bye"),
            MulticastMessage::Probe(_) => write!(f, "Probe"),
            MulticastMessage::Resolve(_) => write!(f, "Resolve"),
        }
    }
}
