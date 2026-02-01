#[macro_export]
macro_rules! wrap_and_report {
    ($level:expr, $error:expr, $message:expr) => {
        {
            let wrapped: color_eyre::eyre::Report = Into::<color_eyre::eyre::Report>::into($error).wrap_err($message);

            tracing::event!($level, error = %wrapped, error_source = ?wrapped.source().unwrap());

            wrapped
        }
    };
}
