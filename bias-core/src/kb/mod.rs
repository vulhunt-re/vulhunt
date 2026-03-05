pub mod id;
pub mod offset_map;
pub mod table;

pub mod block;
pub mod debug;
pub mod function;
pub mod function_summary;
pub mod metadata;
pub mod operand;
pub mod phi;
pub mod string_xref;
pub mod symbol;
pub mod xref;

pub use ahash::{AHashMap, AHashSet, AHasher};
pub use fixedbitset::FixedBitSet;
pub use indexmap::{IndexMap, IndexSet};
pub use offset_map::{OffsetLike, OffsetMap, OffsetValue, OffsetValueWith};
pub use once_cell::sync::Lazy;
pub use ustr::{ustr, Ustr};
pub use uuid::Uuid;

pub const fn uuid(input: &str) -> Uuid {
    if let Ok(uuid) = Uuid::try_parse(input) {
        uuid
    } else {
        panic!("invalid UUID string")
    }
}

#[macro_export]
macro_rules! lazy_ustr {
    ($s:literal) => {
        ::bias_core::kb::Lazy::new(|| ::bias_core::kb::Ustr::from($s))
    };
}
