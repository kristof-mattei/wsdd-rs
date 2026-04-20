pub mod device;
pub mod http;
pub mod udp;

use std::sync::{Arc, LazyLock};

use tokio::sync::RwLock;
use uuid::fmt::Urn;

use crate::constants::WSD_MAX_KNOWN_MESSAGES;
use crate::max_size_deque::MaxSizeDeque;

pub static HANDLED_MESSAGES: LazyLock<Arc<RwLock<MaxSizeDeque<Urn>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(MaxSizeDeque::new(WSD_MAX_KNOWN_MESSAGES))));
