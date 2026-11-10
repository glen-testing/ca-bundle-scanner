pub mod cargo;
pub mod go;
pub mod hex;
pub mod npm;
pub mod perl;
pub mod php;
pub mod python;
pub mod ruby;

use crate::{Ecosystem, ParsedLock, RunConfig};
use anyhow::Result;
use std::path::Path;

pub fn parse(path: &Path, ecosystem: Ecosystem, config: &RunConfig) -> Result<ParsedLock> {
    match ecosystem {
        Ecosystem::Rust => cargo::parse(path, config),
        Ecosystem::Python => python::parse(path, config),
        Ecosystem::Node => npm::parse(path, config.include_dev),
        Ecosystem::Go => go::parse(path),
        Ecosystem::Ruby => ruby::parse(path),
        Ecosystem::Php => php::parse(path, config.include_dev),
        Ecosystem::Hex => hex::parse(path),
        Ecosystem::Perl => perl::parse(path),
    }
}
