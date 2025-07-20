pub mod client;
pub mod host;

use std::sync::{Arc, LazyLock};

use tokio::sync::RwLock;

use crate::max_size_deque::MaxSizeDeque;

static HANDLED_MESSAGES: LazyLock<Arc<RwLock<MaxSizeDeque<String>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(MaxSizeDeque::new(10))));
