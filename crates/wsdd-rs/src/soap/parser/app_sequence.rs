use std::cmp::Ordering;

use thiserror::Error;
use xml::attribute::OwnedAttribute;

use crate::soap::parser::generic::parse_unsigned_int;

/// The `wsd:AppSequence` header block of a received message, see documentation/ws-discovery.pdf, Appendix I.
#[derive(Debug, PartialEq)]
pub struct AppSequence {
    instance_id: u64,
    sequence_id: Option<Box<str>>,
    message_number: u64,
}

#[derive(Error, Clone, Debug, PartialEq)]
pub enum InvalidAppSequence {
    #[error("Missing InstanceId")]
    MissingInstanceId,
    #[error("Missing MessageNumber")]
    MissingMessageNumber,
    #[error("InstanceId is not an unsigned 64-bit number: {}", .0)]
    InvalidInstanceId(Box<str>),
    #[error("MessageNumber is not an unsigned 64-bit number: {}", .0)]
    InvalidMessageNumber(Box<str>),
}

impl AppSequence {
    #[cfg(test)]
    pub fn new(instance_id: u64, sequence_id: Option<&str>, message_number: u64) -> Self {
        Self {
            instance_id,
            sequence_id: sequence_id.map(Box::from),
            message_number,
        }
    }

    pub fn from_attributes(attributes: &[OwnedAttribute]) -> Result<Self, InvalidAppSequence> {
        let mut instance_id = None;
        let mut sequence_id = None;
        let mut message_number = None;

        for attribute in attributes {
            if attribute.name.namespace_ref().is_some() {
                continue;
            }

            match &*attribute.name.local_name {
                "InstanceId" => {
                    instance_id = Some(parse_unsigned_int(&attribute.value).ok_or_else(|| {
                        InvalidAppSequence::InvalidInstanceId(Box::from(&*attribute.value))
                    })?);
                },
                "SequenceId" => sequence_id = Some(Box::from(&*attribute.value)),
                "MessageNumber" => {
                    message_number =
                        Some(parse_unsigned_int(&attribute.value).ok_or_else(|| {
                            InvalidAppSequence::InvalidMessageNumber(Box::from(&*attribute.value))
                        })?);
                },
                _ => {},
            }
        }

        Ok(Self {
            instance_id: instance_id.ok_or(InvalidAppSequence::MissingInstanceId)?,
            sequence_id,
            message_number: message_number.ok_or(InvalidAppSequence::MissingMessageNumber)?,
        })
    }
}

/// `MessageNumber` only orders messages that share `InstanceId` and `SequenceId`.
impl PartialOrd for AppSequence {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.instance_id.cmp(&other.instance_id) {
            Ordering::Equal if self.sequence_id != other.sequence_id => None,
            Ordering::Equal => Some(self.message_number.cmp(&other.message_number)),
            ordering @ (Ordering::Less | Ordering::Greater) => Some(ordering),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use pretty_assertions::assert_eq;
    use xml::attribute::OwnedAttribute;
    use xml::name::OwnedName;

    use crate::soap::parser::app_sequence::{AppSequence, InvalidAppSequence};

    fn attributes(pairs: &[(&str, &str)]) -> Vec<OwnedAttribute> {
        pairs
            .iter()
            .map(|&(name, value)| OwnedAttribute::new(OwnedName::local(name), value))
            .collect()
    }

    #[test]
    fn parses_all_attributes() {
        let app_sequence = AppSequence::from_attributes(&attributes(&[
            ("InstanceId", "1742000334"),
            (
                "SequenceId",
                "urn:uuid:ae0a8b77-0138-11f0-93f3-d45ddf1e11a9",
            ),
            ("MessageNumber", "1"),
        ]));

        assert_eq!(
            app_sequence,
            Ok(AppSequence::new(
                1_742_000_334,
                Some("urn:uuid:ae0a8b77-0138-11f0-93f3-d45ddf1e11a9"),
                1
            ))
        );
    }

    #[test]
    fn parses_without_sequence_id() {
        let app_sequence = AppSequence::from_attributes(&attributes(&[
            ("InstanceId", "1"),
            ("MessageNumber", "2"),
        ]));

        assert_eq!(app_sequence, Ok(AppSequence::new(1, None, 2)));
    }

    #[test]
    fn parses_unsigned_int_lexical_forms() {
        let app_sequence = AppSequence::from_attributes(&attributes(&[
            ("InstanceId", " 007 "),
            ("MessageNumber", "18446744073709551615"),
        ]));

        assert_eq!(app_sequence, Ok(AppSequence::new(7, None, u64::MAX)));
    }

    #[test]
    fn rejects_missing_instance_id() {
        let app_sequence = AppSequence::from_attributes(&attributes(&[("MessageNumber", "2")]));

        assert_eq!(app_sequence, Err(InvalidAppSequence::MissingInstanceId));
    }

    #[test]
    fn rejects_missing_message_number() {
        let app_sequence = AppSequence::from_attributes(&attributes(&[("InstanceId", "1")]));

        assert_eq!(app_sequence, Err(InvalidAppSequence::MissingMessageNumber));
    }

    #[test]
    fn rejects_non_numeric_instance_id() {
        let app_sequence = AppSequence::from_attributes(&attributes(&[
            ("InstanceId", "host-instance-id"),
            ("MessageNumber", "2"),
        ]));

        assert_eq!(
            app_sequence,
            Err(InvalidAppSequence::InvalidInstanceId(Box::from(
                "host-instance-id"
            )))
        );
    }

    #[test]
    fn accepts_message_number_above_unsigned_int() {
        let app_sequence = AppSequence::from_attributes(&attributes(&[
            ("InstanceId", "1"),
            ("MessageNumber", "4294967296"),
        ]));

        assert_eq!(
            app_sequence,
            Ok(AppSequence::new(1, None, u64::from(u32::MAX) + 1))
        );
    }

    #[test]
    fn rejects_message_number_above_u64() {
        let app_sequence = AppSequence::from_attributes(&attributes(&[
            ("InstanceId", "1"),
            ("MessageNumber", "18446744073709551616"),
        ]));

        assert_eq!(
            app_sequence,
            Err(InvalidAppSequence::InvalidMessageNumber(Box::from(
                "18446744073709551616"
            )))
        );
    }

    #[test]
    fn higher_instance_id_is_newer() {
        let last = AppSequence::new(1, Some("urn:uuid:a"), 50);

        assert_eq!(
            AppSequence::new(2, Some("urn:uuid:b"), 0).partial_cmp(&last),
            Some(Ordering::Greater)
        );
    }

    #[test]
    fn lower_instance_id_is_stale() {
        let last = AppSequence::new(2, Some("urn:uuid:a"), 0);

        assert_eq!(
            AppSequence::new(1, Some("urn:uuid:a"), 50).partial_cmp(&last),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn message_number_orders_within_one_sequence() {
        let last = AppSequence::new(1, Some("urn:uuid:a"), 5);

        assert_eq!(
            AppSequence::new(1, Some("urn:uuid:a"), 4).partial_cmp(&last),
            Some(Ordering::Less)
        );
        assert_eq!(
            AppSequence::new(1, Some("urn:uuid:a"), 5).partial_cmp(&last),
            Some(Ordering::Equal)
        );
        assert_eq!(
            AppSequence::new(1, Some("urn:uuid:a"), 6).partial_cmp(&last),
            Some(Ordering::Greater)
        );
    }

    #[test]
    fn message_number_orders_within_the_null_sequence() {
        let last = AppSequence::new(1, None, 5);

        assert_eq!(
            AppSequence::new(1, None, 4).partial_cmp(&last),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn different_sequence_ids_are_unordered() {
        let last = AppSequence::new(1, Some("urn:uuid:a"), 5);

        assert_eq!(
            AppSequence::new(1, Some("urn:uuid:b"), 4).partial_cmp(&last),
            None
        );
        assert_eq!(AppSequence::new(1, None, 4).partial_cmp(&last), None);
    }
}
