use fugue::ir::Address;

use crate::ir::Location;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
#[repr(u8)]
pub enum XRefKind {
    Load,
    Store,
}

impl XRefKind {
    pub fn is_load(&self) -> bool {
        *self == Self::Load
    }

    pub fn is_store(&self) -> bool {
        *self == Self::Store
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct XRef {
    kind: XRefKind,
    from: Location,
    to: Address,
}

impl XRef {
    pub fn load(at: Location, from: Address) -> Self {
        Self {
            kind: XRefKind::Load,
            from: at,
            to: from,
        }
    }

    pub fn store(at: Location, to: Address) -> Self {
        Self {
            kind: XRefKind::Store,
            from: at,
            to,
        }
    }

    pub fn kind(&self) -> XRefKind {
        self.kind
    }

    pub fn source(&self) -> Location {
        self.from
    }

    pub fn target(&self) -> Address {
        self.to
    }
}
