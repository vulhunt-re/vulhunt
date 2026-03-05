use serde::{Deserialize, Serialize};

use crate::ir::Address;
use crate::kb::Ustr;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalFunction {
    address: Address,
    name: Ustr,
}

impl ExternalFunction {
    pub fn new(address: Address, name: Ustr) -> Self {
        Self { address, name }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn name(&self) -> Ustr {
        self.name
    }
}
