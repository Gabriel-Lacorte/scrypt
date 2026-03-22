use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the tracing subscriber with the given log level and format.
pub fn init_logging(level: &str, format: &str) {
    let filter = EnvFilter::try_new(level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    match format {
        "json" => {
            fmt()
                .with_env_filter(filter)
                .json()
                .with_target(true)
                .with_thread_ids(true)
                .init();
        }
        _ => {
            fmt()
                .with_env_filter(filter)
                .with_target(true)
                .with_thread_ids(false)
                .init();
        }
    }
}
