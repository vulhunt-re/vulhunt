pub mod pattern;
pub mod pattern_set;

pub use pattern::{Pattern, PatternError};
pub use pattern_set::{PatternSet, PatternSetError, PatternSetMatchIter};
