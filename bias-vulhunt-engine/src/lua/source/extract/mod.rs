pub mod traits;
pub mod extractor;
pub mod c;

pub use tree_sitter as languages;
pub use self::extractor::{Entity, Extractor, ExtractorError, FileEntities};
pub use self::traits::EntityExtractor;
