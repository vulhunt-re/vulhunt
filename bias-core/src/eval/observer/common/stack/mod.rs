pub mod logger;
pub use logger::StackLogger;

use crate::eval::Configuration;

pub fn configure(config: Configuration) -> Configuration {
    Configuration {
        enable_restores: true,
        ignore_failures: true,
        single_function_analysis: true,
        ..config
    }
}
