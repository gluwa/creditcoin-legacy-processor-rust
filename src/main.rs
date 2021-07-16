#![allow(
    clippy::suspicious_operation_groupings,
    clippy::try_err,
    clippy::wrong_self_convention
)]
#![deny(unused_must_use)]
#![cfg_attr(test, allow(dead_code, unused_imports))]

pub mod ext;
pub mod handler;

#[allow(non_snake_case)]
pub mod protos {
    include!(concat!(env!("OUT_DIR"), "/cc.protos.rs"));
}

use anyhow::Result;
use fern::FormatCallback;
use fern::{colors::Color, Dispatch};
use log::LevelFilter;
use log::Record;
use std::fmt::Arguments;
use std::io::stdout;

use clap::{clap_app, crate_authors, crate_description, crate_version};
use fern::colors::ColoredLevelConfig;
use log::info;

#[cfg(not(feature = "old-sawtooth"))]
pub use sawtooth_sdk as sdk;
#[cfg(feature = "old-sawtooth")]
pub use sawtooth_sdk_compat as sdk;

use crate::sdk::processor::TransactionProcessor;

const DEFAULT_ENDPOINT: &str = "tcp://localhost:4004";
const DEFAULT_GATEWAY: &str = "tcp://localhost:55555";

const TIME_FMT: &str = "%Y-%m-%d %H:%M:%S.%3f";

fn fmt_log(out: FormatCallback, message: &Arguments, record: &Record) {
    let module: &str = record
        .module_path_static()
        .or_else(|| record.module_path())
        .unwrap_or("???");
    let colors = ColoredLevelConfig::new()
        .info(Color::Green)
        .debug(Color::Blue)
        .trace(Color::BrightMagenta);
    out.finish(format_args!(
        "[{} {:<5} {}] {}",
        chrono::Utc::now().format(TIME_FMT),
        colors.color(record.level()),
        module,
        message
    ))
}

fn setup_logs(verbose_count: u64) -> Result<()> {
    let level = match verbose_count {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    Dispatch::new()
        .level(level)
        .level_for("sawtooth_sdk::consensus::zmq_driver", LevelFilter::Error)
        .level_for("sawtooth_sdk::messaging::zmq_stream", LevelFilter::Error)
        .format(fmt_log)
        .chain(stdout())
        .apply()?;

    Ok(())
}

#[cfg(not(all(test, feature = "mock")))]
fn main() -> Result<()> {
    let matches = clap_app!(consensus_engine =>
      (version: crate_version!())
      (author: crate_authors!())
      (about: crate_description!())
      (@arg endpoint: -E --endpoint +takes_value "connection endpoint for validator")
      (@arg gateway: -G --gateway +takes_value "connection endpoint for gateway")
      (@arg old: --old "use compatibility")
      (@arg verbose: -v --verbose +multiple "increase output verbosity")
    )
    .get_matches();

    let endpoint: &str = matches.value_of("endpoint").unwrap_or(DEFAULT_ENDPOINT);
    let gateway: &str = matches.value_of("gateway").unwrap_or(DEFAULT_GATEWAY);

    setup_logs(matches.occurrences_of("verbose"))?;

    info!("ccprocessor-rust ({})", env!("CARGO_PKG_VERSION"));

    info!("ccprocessor-rust connecting to {} ...", endpoint);
    let mut processor = TransactionProcessor::new(endpoint);

    info!("ccprocessor-rust connecting to gateway {} ...", gateway);
    let handler = handler::CCTransactionHandler::new(&mut processor, gateway);

    processor.add_handler(&handler);
    processor.start();

    info!("ccprocessor-rust exiting ...");

    handler.updater.exit();

    Ok(())
}
