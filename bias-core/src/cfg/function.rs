use fugue::ir::Address;

use crate::kb::function::FunctionInfo;
use crate::kb::AHashMap;

pub type FunctionStarts = AHashMap<Address, FunctionInfo>;
