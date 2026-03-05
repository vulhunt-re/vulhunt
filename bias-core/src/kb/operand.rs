use std::fmt::Display;

use fugue::ir::convention::PrototypeOperand;

use crate::cio::TypeDB;
use crate::ir::{Address, BitSize, Term, Type, Var};
use crate::lifter::Lifter;

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum Operand {
    Global(Address, usize),
    Stack(i64, usize),
    Register(Var),
    Indirect(Box<Self>, usize, usize),
}

impl Display for Operand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Global(address, size) => write!(f, "{}:{}", address, size * 8),
            Self::Stack(offset, size) => {
                if *offset < 0 {
                    write!(f, "sp-{}:{}", offset.abs(), size * 8)
                } else {
                    write!(f, "sp+{}:{}", offset, size * 8)
                }
            }
            Self::Register(var) => {
                write!(f, "reg{:x}:{}", var.offset(), var.nbits())
            }
            Self::Indirect(operand, offset, size) => {
                write!(f, "*({operand}")?;
                if *offset != 0 {
                    write!(f, "+{}", offset)?;
                }
                write!(f, "):{}", size * 8)
            }
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct TypedOperand {
    operand: Operand,
    type_: Term<Type>,
}

impl TypedOperand {
    pub fn new(operand: impl Into<Operand>, type_: impl Into<Term<Type>>) -> Self {
        Self {
            operand: operand.into(),
            type_: type_.into(),
        }
    }

    #[inline]
    pub fn operand(&self) -> &Operand {
        &self.operand
    }

    #[inline]
    pub fn type_(&self) -> &Term<Type> {
        &self.type_
    }
}

#[derive(Clone)]
pub struct OperandBuilder<'a> {
    lifter: &'a Lifter,
    typedb: &'a TypeDB,
}

impl<'a> OperandBuilder<'a> {
    pub fn new(lifter: &'a Lifter, typedb: &'a TypeDB) -> Self {
        Self { lifter, typedb }
    }

    #[inline]
    pub fn named_type(&self, name: impl AsRef<str>) -> Option<Term<Type>> {
        self.typedb
            .get_type_for(name.as_ref(), self.lifter.address_bits())
    }

    #[inline]
    pub fn pointer(&self, address: impl Into<Address>) -> Operand {
        Operand::global(address, self.lifter.address_bytes())
    }

    #[inline]
    pub fn stack_pointer(&self, offset: i64) -> Operand {
        Operand::stack(offset, self.lifter.address_bytes())
    }

    #[inline]
    pub fn indirect_via(&self, operand: Operand, derefs: usize, bytes: usize) -> Operand {
        if derefs == 0 {
            Operand::indirect(operand, 0, bytes)
        } else {
            self.indirect_via(
                Operand::indirect(operand, 0, self.lifter.address_bytes()),
                derefs - 1,
                bytes,
            )
        }
    }

    pub fn from_prototype(&self, operand: &PrototypeOperand) -> (Operand, Option<Operand>) {
        match operand {
            PrototypeOperand::Register { varnode, .. } => {
                let reg = Operand::register(Var::new0(
                    self.lifter.register_space(),
                    varnode.offset(),
                    varnode.size() as u32 * 8,
                ));
                (reg, None)
            }
            PrototypeOperand::StackRelative(offset) => {
                let stk = Operand::stack(*offset as i64, self.lifter.address_bytes());
                (stk, None)
            }
            PrototypeOperand::RegisterJoin {
                first_varnode,
                second_varnode,
                ..
            } => {
                let reg1 = Operand::register(Var::new0(
                    self.lifter.register_space(),
                    first_varnode.offset(),
                    first_varnode.size() as u32 * 8,
                ));
                let reg2 = Operand::register(Var::new0(
                    self.lifter.register_space(),
                    second_varnode.offset(),
                    second_varnode.size() as u32 * 8,
                ));
                (reg1, Some(reg2))
            }
        }
    }
}

impl Operand {
    #[inline]
    pub fn global(address: impl Into<Address>, bytes: usize) -> Self {
        Self::Global(address.into(), bytes)
    }

    #[inline]
    pub fn as_global_access(&self) -> Option<(Address, usize)> {
        if let Self::Global(addr, size) = self {
            Some((*addr, *size))
        } else {
            None
        }
    }

    #[inline]
    pub fn stack(offset: i64, bytes: usize) -> Self {
        Self::Stack(offset, bytes)
    }

    #[inline]
    pub fn as_stack_access(&self) -> Option<(i64, usize)> {
        if let Self::Stack(off, size) = self {
            Some((*off, *size))
        } else {
            None
        }
    }

    #[inline]
    pub fn register(register: impl Into<Var>) -> Self {
        let register = register.into();
        assert!(register.is_register());
        Self::Register(register)
    }

    #[inline]
    pub fn as_register(&self) -> Option<Var> {
        if let Self::Register(var) = self {
            Some(*var)
        } else {
            None
        }
    }

    #[inline]
    pub fn indirect(via: impl Into<Self>, offset: usize, bytes: usize) -> Self {
        Self::Indirect(Box::new(via.into()), offset, bytes)
    }

    #[inline]
    pub fn size(&self) -> usize {
        match self {
            Self::Global(_, size) | Self::Stack(_, size) | Self::Indirect(_, _, size) => *size,
            Self::Register(reg) => reg.nbits() as usize / 8,
        }
    }
}
