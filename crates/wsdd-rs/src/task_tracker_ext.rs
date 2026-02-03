use tokio::task::JoinHandle;

use crate::utils::task::spawn_with_name;

pub trait TaskTrackerExt {
    #[track_caller]
    fn spawn_with_name<F>(&self, name: &str, task: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
}

impl TaskTrackerExt for tokio_util::task::TaskTracker {
    #[inline]
    #[track_caller]
    fn spawn_with_name<F>(&self, name: &str, task: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        spawn_with_name(name, self.track_future(task))
    }
}
