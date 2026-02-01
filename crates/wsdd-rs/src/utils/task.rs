use tokio::task::{Builder, JoinHandle};

#[track_caller]
pub fn spawn_with_name<Fut>(name: &str, future: Fut) -> JoinHandle<Fut::Output>
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    let builder: Builder = Builder::new();

    let builder = builder.name(name);

    // weirdly enough tokio::spawn returns a JoinHandle, but the builder, which contains the same code, and no ? to fail, returns a Result of JoinHandle

    // builder: https://github.com/tokio-rs/tokio/blob/56870433289f6906716c9d9b2a28da5c9e76352e/tokio/src/task/builder.rs#L87-L98
    // direct spawn: https://github.com/tokio-rs/tokio/blob/56870433289f6906716c9d9b2a28da5c9e76352e/tokio/src/task/spawn.rs#L166-L177

    // hence why we unwrap here. The builder is unstable, so we'll need to live with that
    builder
        .spawn(future)
        .expect("Launching task should not fail")
}
