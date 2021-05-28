use std::path::PathBuf;

use anyhow::Result;
use glob::{glob, GlobError};

fn main() -> Result<()> {
    let protos: Result<Vec<PathBuf>, GlobError> = glob("proto/*.proto")?.collect();
    let protos = protos?;
    prost_build::compile_protos(&protos, &[PathBuf::from("proto")])?;
    Ok(())
}
