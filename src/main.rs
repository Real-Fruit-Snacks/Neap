mod config;
mod error;

use log;

fn main() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Off)
        .try_init();

    log::info!("neap v{}", config::VERSION);
}
