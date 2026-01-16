use tokio::task::JoinHandle;

use crate::shutdown::Shutdown;

pub mod env;
pub mod task;

pub async fn flatten_shutdown_handle(handle: JoinHandle<Shutdown>) -> Shutdown {
    match handle.await {
        Ok(shutdown) => shutdown,
        Err(join_error) => Shutdown::UnexpectedError(join_error.into()),
    }
}

/// Utility struct to format the elements using the Display trait instead of the Debug trait
#[repr(transparent)]
pub struct SliceDisplay<'s, T>(pub &'s [T]);

impl<T: std::fmt::Display> std::fmt::Display for SliceDisplay<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut iter = self.0.iter();

        let Some(first) = iter.next() else {
            return Ok(());
        };

        write!(f, "[{}", first)?;

        for next in iter {
            write!(f, ", {}", next)?;
        }

        write!(f, "]")?;

        Ok(())
    }
}
