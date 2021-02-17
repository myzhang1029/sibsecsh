#[macro_use]
extern crate log;
extern crate home;
extern crate serde;
extern crate simplelog;
extern crate toml;

mod config;
#[macro_use]
mod error;

use simplelog::{CombinedLogger, LevelFilter, TermLogger, TerminalMode, WriteLogger};

fn main() {
    let mut configuration: config::Config = Default::default();
    let load_result = configuration.load_all_possible();
    let log_file = match configuration.open_log() {
        Ok(f) => f,
        Err(e) => panic_gracefully!("Cannot open log file: {:?}", e),
    };

    if let Err(e) = CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Warn,
            simplelog::Config::default(),
            TerminalMode::Mixed,
        ),
        WriteLogger::new(LevelFilter::Info, simplelog::Config::default(), log_file),
    ]) {
        panic_gracefully!("Cannot create logger: {:?}", e);
    }

    match load_result {
        Ok(_) => (),
        Err(_) => warn!("No configuration supplied!"),
    }
}
