use color_eyre::eyre;
use tokio::task::JoinHandle;

pub mod env;
pub mod task;

/// Use this when you have a `JoinHandle<Result<T, E>>`
/// and you want to use it with `tokio::try_join!`
/// when the task completes with an `Result::Err`
/// the `JoinHandle` itself will be `Result::Ok` and thus not
/// trigger the `tokio::try_join!`. This function flattens the 2:
/// `Result::Ok(T)` when both the join-handle AND
/// the result of the inner function are `Result::Ok`, and `Result::Err`
/// when either the join failed, or the inner task failed
pub async fn flatten_handle<T, E>(handle: JoinHandle<Result<T, E>>) -> Result<T, eyre::Report>
where
    eyre::Report: From<E>,
{
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => Err(error.into()),
        Err(error) => Err(error.into()),
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
