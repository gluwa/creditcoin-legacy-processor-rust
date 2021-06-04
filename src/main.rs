#![warn(clippy::pedantic)]

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

use sawtooth_sdk::processor::TransactionProcessor;

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

fn main() -> Result<()> {
    let matches = clap_app!(consensus_engine =>
      (version: crate_version!())
      (author: crate_authors!())
      (about: crate_description!())
      (@arg endpoint: -E --endpoint +takes_value "connection endpoint for validator")
      (@arg gateway: -G --gateway +takes_value "connection endpoint for gateway")
      (@arg verbose: -v --verbose +multiple "increase output verbosity")
    )
    .get_matches();

    let endpoint: &str = matches.value_of("endpoint").unwrap_or(DEFAULT_ENDPOINT);
    let gateway: &str = matches.value_of("gateway").unwrap_or(DEFAULT_GATEWAY);

    let level = match matches.occurrences_of("verbose") {
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

    info!("ccprocessor-rust ({})", env!("CARGO_PKG_VERSION"));

    info!("ccprocessor-rust connecting to {} ...", endpoint);
    let mut processor = TransactionProcessor::new(endpoint);

    info!("ccprocessor-rust connecting to gateway {} ...", gateway);
    let handler = handler::CCTransactionHandler::new(&processor, gateway);

    processor.add_handler(&handler);
    processor.start();

    info!("ccprocessor-rust exiting ...");

    handler.updater.exit();

    Ok(())
}

// fn main() {
//     let s = handler::sha512_id(&handler::compress(
//         "04a196d6af44a78637ccf6971543f5ff604c6bb77183c70985ad3626fb2c2058779502da4ad981b6818a0e6eb2958c6424143d08bc3106b4e1d49bc8fe86a7e10f",
//     ).unwrap().as_bytes());
//     println!("{:?}", s)
// }
