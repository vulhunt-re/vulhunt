use thiserror::Error;

use crate::fugue;
use crate::prelude::*;

#[derive(Debug, Error)]
pub enum DecompilerError {
    #[error("could not apply fixup: {0}")]
    ApplyFixup(cxx::Exception),
    #[error("could not clear fixup: {0}")]
    ClearFixup(cxx::Exception),
    #[error("could not register fixup: {0}")]
    RegisterFixup(cxx::Exception),
    #[error("could not reset decompiler to a clean state: {0}")]
    ClearAll(cxx::Exception),
    #[error("could not decompile function at {0}: {1}")]
    Decompile(Address, cxx::Exception),
    #[error("could not initialise decompiler context: {0}")]
    Init(cxx::Exception),
    #[error("could not use given type as a function type")]
    InvalidFunctionType,
    #[error("invalid regex: {0}")]
    InvalidRegex(regex::Error),
    #[error("{0}")]
    Ffi(&'static str),
    #[error("could not generate signature for function at {0}: {1}")]
    GenerateSignature(Address, cxx::Exception),
    #[error("could not parse decompiled output: {0:?}")]
    ParseAst(weggli::WeggliError),
    #[error("could not construct query tree: {0:?}")]
    QueryAst(weggli::WeggliError),
    #[error("could not add search path: {0}")]
    SearchPath(cxx::Exception),
    #[error("could not add search paths: {0}")]
    SearchPathDiscover(fugue::ir::error::Error),
    #[error("invalid argument: {0}; it must be of the form var=regex")]
    RegexArg(String),
    #[error("could not remove type: {0}")]
    RemoveType(cxx::Exception),
    #[error("could not set type for {0}: {1}")]
    SetType(Address, cxx::Exception),
    #[error("could not set comment for {0} in function {1}: {2}")]
    SetComment(Address, Address, cxx::Exception),
    #[error("could not override flow for {0} in function {1}: {2}")]
    FlowOverride(Address, Address, cxx::Exception),
    #[error("could not override jump table for {0} in function {1}: {2}")]
    JumpTableOverride(Address, Address, cxx::Exception),
    #[error("could not delete comment for {0} in function {1}: {2}")]
    DeleteComment(Address, Address, cxx::Exception),
    #[error("could not define function at {0}: {1}")]
    SetSymbol(Address, cxx::Exception),
    #[error("could not set property on address range from {0} with size {1}: {2}")]
    SetRangeProperty(Address, usize, cxx::Exception),
    #[error("could not set non-returning flag for {0}: {1}")]
    SetNonReturningFunction(Address, cxx::Exception),
    #[error("could not get context variable: {0}")]
    GetContext(cxx::Exception),
    #[error("could not set context variable: {0}")]
    SetContext(cxx::Exception),
    #[error("could not create builder for type: {0}")]
    TypeBuilder(cxx::Exception),
    #[error("could not get architecture information: {0}")]
    GetArchInfo(cxx::Exception),
}
