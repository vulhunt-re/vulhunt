use crate::VulHuntModuleDir;

pub mod api;
pub use api::{CallSiteContext, CheckResult, FunctionContext, OperandInfo};

pub mod checker;
pub use checker::{Checker, CheckerArch, CheckerContext, CheckerError};

pub mod ctypes;
pub use ctypes::{CPrototype, CPrototypeExtractor};

pub mod modules;

pub mod project;
pub use project::ProjectHandle;

pub mod preprocess;
pub use preprocess::parse_and_preprocess;

pub mod source;

pub mod scope;
pub use scope::CheckScope;

pub mod types;

pub use mlua;
use mlua::ObjectLike;

pub mod query;
pub use query::{
    CallsFromQuery, CallsToQuery, FunctionQuery, FunctionQueryCallOpts, FunctionQueryTarget,
};

pub fn new_vm(module_dir: impl Into<VulHuntModuleDir>) -> Result<mlua::Lua, mlua::Error> {
    let module_dir = module_dir.into();
    let context = unsafe { mlua::Lua::unsafe_new() };

    // Load the Rust FFI ctors
    api::AddressValue::register(&context)?;
    api::PatternMatcher::register(&context)?;
    api::RegexMatcher::register(&context)?;
    types::BitVec::register(&context)?;
    types::IRTerm::register(&context)?;

    // Load the prelude
    context
        .load(&*api::PRELUDE)
        .set_name("bias_core::prelude")
        .exec()?;

    // Load the prelude
    {
        let fun = context
            .load(&*api::FUNCTIONAL)
            .set_name("lua::functional")
            .call::<mlua::Table>(())?;

        fun.call::<()>(())?;
    }

    modules::register_module_loader(&context, module_dir.as_deref())?;

    Ok(context)
}
