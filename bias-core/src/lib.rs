extern crate self as bias_core;

pub use fugue;

pub mod any {
    pub use bias_core_derive::ProvidesStaticType;
    pub use gazebo::any::AnyLifetime;
}
#[doc(hidden)]
pub use gazebo;

pub mod analyses;
pub mod arch;
pub mod caches;
pub mod cfg;
pub mod cio;
pub mod data;
pub mod domains;
pub mod efi;
pub mod eval;
pub mod inject;
pub mod ir;
pub mod kb;
pub mod lifter;
pub mod loader;
pub mod posix;
pub mod prelude;
pub mod project;
pub mod region;
pub mod symbols;
pub mod types;
pub mod windows;

#[cfg(feature = "decompiler")]
pub mod decompiler;

pub use loader::{EFILoader, PELoader, TELoader};
pub use project::{Project, ProjectConfig};
