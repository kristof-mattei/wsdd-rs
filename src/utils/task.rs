use tokio::task::{Builder, JoinHandle};

pub fn spawn_with_name<Fut>(name: &str, future: Fut) -> std::io::Result<JoinHandle<Fut::Output>>
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    let builder: Builder = Builder::new();

    let builder = builder.name(name);

    builder.spawn(future)
}
