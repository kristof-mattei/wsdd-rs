pub mod builder;
pub mod parser;

pub trait MessageType {
    fn message_type(&self) -> &str;
}

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

impl MessageType for UnicastMessage {
    fn message_type(&self) -> &str {
        match *self {
            UnicastMessage::ProbeMatches(_) => "ProbeMatches",
            UnicastMessage::ResolveMatches(_) => "ResolveMatches",
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
