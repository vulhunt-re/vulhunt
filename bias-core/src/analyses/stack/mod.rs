use std::fmt::Display;
use std::ops::Range;

use iset::IntervalSet;

use crate::prelude::{Address, BitSize, Operand, ToAddress, Var};

pub mod aliases;
pub mod possibly_uninit;
pub mod reaching_constants;
pub mod reaching_definitions;
pub mod reaching_provenance;
pub mod reaching_uninit;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct StackAccess {
    pub offset: i64,
    pub size: usize,
}

impl Display for StackAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.offset < 0 {
            write!(f, "sp-{:#x} ({})", -self.offset, self.size)
        } else {
            write!(f, "sp+{:#x} ({})", self.offset, self.size)
        }
    }
}

impl StackAccess {
    pub fn new(offset: i64, size: usize) -> Self {
        Self { offset, size }
    }

    pub fn offset(&self) -> i64 {
        self.offset
    }

    pub fn nbytes(&self) -> usize {
        self.size
    }
}

impl BitSize for StackAccess {
    fn nbits(&self) -> u32 {
        self.nbytes() as u32 * 8
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum StackVarDef {
    Var(Var),
    Stack(StackAccess),
}

impl Display for StackVarDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Var(var) => var.fmt(f),
            Self::Stack(access) => access.fmt(f),
        }
    }
}

impl From<Var> for StackVarDef {
    fn from(v: Var) -> Self {
        Self::Var(v)
    }
}

impl From<StackAccess> for StackVarDef {
    fn from(v: StackAccess) -> Self {
        Self::Stack(v)
    }
}

impl StackVarDef {
    pub fn new(v: impl Into<StackVarDef>) -> Self {
        v.into()
    }

    pub fn stack(offset: i64, size: usize) -> Self {
        Self::Stack(StackAccess { offset, size })
    }

    pub fn is_stack(&self) -> bool {
        matches!(self, Self::Stack(_))
    }

    #[inline(always)]
    fn if_var(&self, f: impl Fn(&Var) -> bool) -> bool {
        matches!(self, Self::Var(v) if f(v))
    }

    #[inline(always)]
    fn as_var<T>(&self, f: impl Fn(&Var) -> Option<T>) -> Option<T> {
        if let Self::Var(v) = self {
            f(v)
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn stack_delta(&self) -> Option<i64> {
        if let Self::Stack(StackAccess { offset, .. }) = self {
            Some(*offset)
        } else {
            None
        }
    }

    pub fn is_register(&self) -> bool {
        self.if_var(Var::is_register)
    }

    pub fn is_temporary(&self) -> bool {
        self.if_var(Var::is_temporary)
    }

    pub fn is_address(&self) -> bool {
        self.if_var(Var::is_address)
    }

    pub fn address(&self) -> Option<Address> {
        self.as_var(Var::address)
    }

    pub fn nbytes(&self) -> usize {
        match self {
            Self::Var(v) => v.nbits() as usize / 8,
            Self::Stack(StackAccess { size, .. }) => *size,
        }
    }
}

impl ToAddress for StackVarDef {
    #[inline(always)]
    fn to_address(&self) -> Option<Address> {
        self.address()
    }
}

impl BitSize for StackVarDef {
    fn nbits(&self) -> u32 {
        match self {
            Self::Var(v) => v.nbits(),
            Self::Stack(StackAccess { size, .. }) => (size * 8) as u32,
        }
    }
}

impl From<StackVarDef> for Operand {
    fn from(slf: StackVarDef) -> Self {
        match slf {
            StackVarDef::Var(reg) => Operand::register(reg),
            StackVarDef::Stack(StackAccess { offset, size }) => Operand::stack(offset, size),
        }
    }
}

#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
pub struct StackView {
    intervals: IntervalSet<i64>,
}

impl StackView {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn intervals(&self) -> &IntervalSet<i64> {
        &self.intervals
    }

    pub fn insert(&mut self, access: StackAccess) {
        let range = access.offset..access.offset + (access.size as i64);
        self.intervals.insert(range);
    }

    pub fn parent(&self, access: &StackAccess) -> Option<StackAccess> {
        let range = access.offset..access.offset + (access.size as i64);
        let overlaps = self.intervals.iter(range.clone());

        let ivlen = |iv: &Range<i64>| iv.end - iv.start;
        overlaps.max_by_key(ivlen).and_then(|iv| {
            if iv.start <= range.start && iv.end >= range.end {
                let size = ivlen(&iv) as usize;
                Some(StackAccess::new(iv.start, size))
            } else {
                None
            }
        })
    }
}
