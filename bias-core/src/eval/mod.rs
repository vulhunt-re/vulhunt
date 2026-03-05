use std::any::Any;
use std::borrow::{Borrow, BorrowMut, Cow};
use std::fmt::Display;
use std::ops::{Neg, Not, Range};

use ahash::{AHashMap, AHashSet};
use fugue::bv::BitVec;
use fugue::bytes::{Order, BE, LE};
use fugue::ir::convention::PrototypeOperand;
use fugue::ir::il::traits::TranslatorDisplay;
use fugue::ir::Address;
use fuguex_state::flat::FlatState;
use fuguex_state::paged::{PagedState, Segment as LoadedSegment};
pub use fuguex_state::pcode::Error as StateError;
use fuguex_state::pcode::PCodeState;
use fuguex_state::traits::{State, StateOps};
use itertools::{Itertools, Position};
use smallvec::SmallVec;
use thiserror::Error;
use ustr::Ustr;

use crate::any::AnyLifetime;
use crate::cfg::insn::InsnTable;
use crate::inject::{InjectionOperand, InjectionStub};
use crate::ir::traits::{BitSize, ToAddress};
use crate::ir::{BinOp, BinRel, BranchTarget, Expr, Insn, Location, Stmt, Term, Type, UnOp, Var};
use crate::kb::block::CodeBlock;
use crate::kb::function::Function;
use crate::kb::function_summary::{FunctionSummary, FunctionSummaryId};
use crate::kb::id::Identifiable;
use crate::project::ProjectContext;

pub mod observer;
pub mod resolver;
pub mod strategy;
pub mod traits;

use self::observer::{Observer, ObserverError, ObserverId};
use self::strategy::{DefaultStrategy, PredicatedLocation, Strategy};

pub trait IRContext: Any + 'static {
    fn read_program_counter(&self) -> Result<Address, StateError>;
    fn write_program_counter(&mut self, value: Address) -> Result<(), StateError>;

    fn read_stack_pointer(&self) -> Result<Address, StateError>;
    fn write_stack_pointer(&mut self, value: Address) -> Result<(), StateError>;

    fn read_bytes(&self, addr: Address, n: usize) -> Result<&[u8], StateError>;
    fn write_bytes(&mut self, addr: Address, bytes: &[u8]) -> Result<(), StateError>;

    fn read_addr(&self, addr: Address, bits: u32) -> Result<BitVec, StateError>;
    fn write_addr(&mut self, addr: Address, val: &BitVec) -> Result<(), StateError>;

    fn read_var(&self, var: &Var) -> Result<BitVec, StateError>;
    fn read_var_addr(&self, var: &Var) -> Result<Address, StateError>;
    fn write_var(&mut self, var: &Var, val: &BitVec) -> Result<(), StateError>;
    fn write_var_addr(&mut self, var: &Var, addr: &Address) -> Result<(), StateError>;

    fn read_pointer(&self, addr: Address) -> Result<Address, StateError>;
    fn write_pointer(&mut self, addr: Address, val: Address) -> Result<(), StateError>;

    fn read_operand(&self, operand: &PrototypeOperand) -> Result<BitVec, StateError>;
    fn write_operand(&mut self, operand: &PrototypeOperand, val: &BitVec)
        -> Result<(), StateError>;

    fn memory(&self) -> &PagedState<u8>;
    fn memory_mut(&mut self) -> &mut PagedState<u8>;

    fn freeze(&self) -> Box<dyn Any>;
    fn restore(&mut self, old: &Box<dyn Any>);
}

macro_rules! impl_context {
    ($order:tt) => {
        impl IRContext for PCodeState<u8, $order> {
            fn freeze(&self) -> Box<dyn Any> {
                Box::new(<PCodeState<u8, $order> as State>::fork(self))
            }

            fn restore(&mut self, old: &Box<dyn Any>) {
                let old_slf = old.downcast_ref::<Self>().expect("downcast from Self");

                <PCodeState<u8, $order> as State>::restore(self, old_slf)
            }

            fn memory(&self) -> &PagedState<u8> {
                PCodeState::<u8, $order>::memory(self)
            }

            fn memory_mut(&mut self) -> &mut PagedState<u8> {
                PCodeState::<u8, $order>::memory_mut(self)
            }

            fn read_program_counter(&self) -> Result<Address, StateError> {
                self.program_counter_value()
            }

            fn write_program_counter(&mut self, value: Address) -> Result<(), StateError> {
                self.set_program_counter_value(value)
            }

            fn read_stack_pointer(&self) -> Result<Address, StateError> {
                self.stack_pointer_value()
            }

            fn write_stack_pointer(&mut self, value: Address) -> Result<(), StateError> {
                self.set_stack_pointer_value(value)
            }

            fn read_pointer(&self, address: Address) -> Result<Address, StateError> {
                self.get_pointer(address)
            }

            fn write_pointer(&mut self, address: Address, val: Address) -> Result<(), StateError> {
                let val =
                    BitVec::from_u64(u64::from(val), self.memory_space_ref().address_size() * 8);
                self.write_addr(address, &val)
            }

            fn read_bytes(&self, addr: Address, n: usize) -> Result<&[u8], StateError> {
                self.memory()
                    .view_values(u64::from(addr), n)
                    .map_err(StateError::Memory)
            }

            fn write_bytes(&mut self, addr: Address, bytes: &[u8]) -> Result<(), StateError> {
                self.memory_mut()
                    .view_values_mut(u64::from(addr), bytes.len())
                    .map_err(StateError::Memory)?
                    .copy_from_slice(bytes);
                Ok(())
            }

            fn read_addr(&self, addr: Address, bits: u32) -> Result<BitVec, StateError> {
                debug_assert!(bits % 8 == 0);

                let offset = u64::from(addr);
                let bytes = bits as usize / 8;

                let view = self
                    .memory()
                    .view_values(offset, bytes)
                    .map_err(StateError::Memory)?;

                Ok(if <$order as Order>::ENDIAN.is_big() {
                    BitVec::from_be_bytes(view)
                } else {
                    BitVec::from_le_bytes(view)
                })
            }

            fn write_addr(&mut self, addr: Address, val: &BitVec) -> Result<(), StateError> {
                debug_assert!(val.nbits() % 8 == 0);

                let offset = u64::from(addr);
                let bytes = val.nbits() as usize / 8;

                let view = self
                    .memory_mut()
                    .view_values_mut(offset, bytes)
                    .map_err(StateError::Memory)?;

                if <$order as Order>::ENDIAN.is_big() {
                    val.to_be_bytes(view)
                } else {
                    val.to_le_bytes(view)
                }

                Ok(())
            }

            fn read_operand(&self, operand: &PrototypeOperand) -> Result<BitVec, StateError> {
                match operand {
                    PrototypeOperand::Register { varnode, .. } => self.read_var(&Var::new(
                        self.registers().address_space_ref(),
                        varnode.offset(),
                        varnode.size() as u32 * 8,
                        0,
                    )),
                    PrototypeOperand::StackRelative(offset) => {
                        let stack_base = self.read_stack_pointer()?;
                        let addr = stack_base + *offset;

                        self.read_var(&Var::new(
                            self.memory().address_space_ref(),
                            addr.into(),
                            self.memory().address_space_ref().address_size() as u32,
                            0,
                        ))
                    }
                    PrototypeOperand::RegisterJoin {
                        first_varnode,
                        second_varnode,
                        ..
                    } => {
                        // high
                        let first = self.read_var(&Var::new(
                            self.registers().address_space_ref(),
                            first_varnode.offset(),
                            first_varnode.size() as u32 * 8,
                            0,
                        ))?;
                        // low
                        let second = self.read_var(&Var::new(
                            self.registers().address_space_ref(),
                            second_varnode.offset(),
                            second_varnode.size() as u32 * 8,
                            0,
                        ))?;

                        let bits = first.bits() + second.bits();
                        Ok(
                            first.unsigned_cast(bits) << second.nbits()
                                | second.unsigned_cast(bits),
                        )
                    }
                }
            }

            fn write_operand(
                &mut self,
                operand: &PrototypeOperand,
                val: &BitVec,
            ) -> Result<(), StateError> {
                match operand {
                    PrototypeOperand::Register { varnode, .. } => self.write_var(
                        &Var::new(
                            self.registers().address_space_ref(),
                            varnode.offset(),
                            varnode.size() as u32 * 8,
                            0,
                        ),
                        val,
                    ),
                    PrototypeOperand::StackRelative(offset) => {
                        let stack_base = self.read_stack_pointer()?;
                        let addr = stack_base + *offset;

                        self.write_var(
                            &Var::new(
                                self.memory().address_space_ref(),
                                addr.into(),
                                self.memory().address_space_ref().address_size() as u32,
                                0,
                            ),
                            val,
                        )
                    }
                    PrototypeOperand::RegisterJoin {
                        first_varnode,
                        second_varnode,
                        ..
                    } => {
                        // high
                        let first = Var::new(
                            self.registers().address_space_ref(),
                            first_varnode.offset(),
                            first_varnode.size() as u32 * 8,
                            0,
                        );
                        // low
                        let second = Var::new(
                            self.registers().address_space_ref(),
                            second_varnode.offset(),
                            second_varnode.size() as u32 * 8,
                            0,
                        );

                        let bits = (first.nbits() + second.nbits()) as usize;
                        let val = if val.bits() != bits {
                            val.unsigned_cast(bits)
                        } else {
                            val.clone()
                        };

                        // first is upper half
                        let first_val = (&val >> second.nbits()).cast(first.nbits() as usize);
                        let second_val = val.unsigned_cast(second.nbits() as usize);

                        self.write_var(&first, &first_val)?;
                        self.write_var(&second, &second_val)?;

                        Ok(())
                    }
                }
            }

            fn write_var(&mut self, var: &Var, val: &BitVec) -> Result<(), StateError> {
                debug_assert!(var.nbits() % 8 == 0);
                debug_assert!(var.nbits() == val.nbits());

                let offset = var.offset();
                let bytes = var.nbits() as usize / 8;

                let view = if var.is_register() {
                    self.registers_mut()
                        .view_values_mut(offset, bytes)
                        .map_err(StateError::Register)?
                } else if var.is_temporary() {
                    self.temporaries_mut()
                        .view_values_mut(offset, bytes)
                        .map_err(StateError::Temporary)?
                } else {
                    self.memory_mut()
                        .view_values_mut(offset, bytes)
                        .map_err(StateError::Memory)?
                };

                if <$order as Order>::ENDIAN.is_big() {
                    val.to_be_bytes(view)
                } else {
                    val.to_le_bytes(view)
                }

                Ok(())
            }

            fn write_var_addr(&mut self, var: &Var, addr: &Address) -> Result<(), StateError> {
                let bits = var.nbits() as usize;
                let bv = BitVec::from_u64(u64::from(*addr), bits);

                self.write_var(var, &bv)
            }

            fn read_var(&self, var: &Var) -> Result<BitVec, StateError> {
                debug_assert!(var.nbits() % 8 == 0);

                let offset = var.offset();
                let bytes = var.nbits() as usize / 8;

                let view = if var.is_register() {
                    self.registers()
                        .view_values(offset, bytes)
                        .map_err(StateError::Register)?
                } else if var.is_temporary() {
                    self.temporaries()
                        .view_values(offset, bytes)
                        .map_err(StateError::Temporary)?
                } else {
                    self.memory()
                        .view_values(offset, bytes)
                        .map_err(StateError::Memory)?
                };

                Ok(if <$order as Order>::ENDIAN.is_big() {
                    BitVec::from_be_bytes(view)
                } else {
                    BitVec::from_le_bytes(view)
                })
            }

            fn read_var_addr(&self, var: &Var) -> Result<Address, StateError> {
                let mut addr = self.read_var(var)?;
                if addr.bits() > 64 {
                    addr.unsigned_cast_assign(64);
                }
                Ok(addr.to_address().unwrap())
            }
        }
    };
}

impl_context!(BE);
impl_context!(LE);

#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Configuration(&'static str),
    #[error(transparent)]
    Context(#[from] StateError),
    #[error("attempt to divide by zero at {0}")]
    DivideByZero(Location),
    #[error("invalid access of {1} at {0}")]
    InvalidAccess(Location, Var),
    #[error("address cannot be represented in 64-bits at {0}")]
    InvalidAddess(Location),
    #[error("invalid instruction at {0}")]
    InvalidInstruction(Address),
    #[error("no free space for new static mapping of size {0}")]
    NoFreeSpace(usize),
    #[error("no viable choice for expression {0}")]
    NoViableChoice(Term<Expr>),
    #[error(transparent)]
    Observer(Box<dyn std::error::Error + Send + Sync>),
    #[error("unhandled branch to external {1} at {0}")]
    UnhandledExternal(Address, FunctionSummaryId),
    #[error("unimplemented operation at {0}")]
    UnimplementedOp(Location),
    #[error("unsupported cast at {0}")]
    UnsupportedCast(Location),
    #[error("restore is not supported")]
    UnsupportedRestore,
}

pub type EvalError = Error;

impl From<ObserverError> for Error {
    fn from(e: ObserverError) -> Self {
        match e {
            ObserverError::Tracer(e) => e,
            ObserverError::TracerState(e) => Self::Context(e),
            ObserverError::Observer(e) => Self::Observer(e),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AccessKind {
    Load(BitVec),
    Store(BitVec),
    Branch(usize), // with position
    Invalid,
}

impl AccessKind {
    pub fn is_load(&self) -> bool {
        matches!(self, Self::Load(_))
    }

    pub fn is_store(&self) -> bool {
        matches!(self, Self::Store(_))
    }

    pub fn is_branch(&self) -> bool {
        matches!(self, Self::Branch(_))
    }

    pub fn is_valid(&self) -> bool {
        !self.is_invalid()
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self, Self::Invalid)
    }

    pub fn value(&self) -> Option<&BitVec> {
        match self {
            Self::Load(ref v) | Self::Store(ref v) => Some(v),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Access {
    pub location: Location,
    pub kind: AccessKind,
    pub variable: Var,
}

impl Access {
    pub fn address(&self) -> Address {
        self.location.address
    }

    pub fn position(&self) -> usize {
        self.location.position
    }
}

#[derive(Debug, Clone)]
pub enum Bound {
    None,
    Count(usize),
    StopBefore(Address),
    StopAfter(Address),
    StopAfterAnyOf(AHashSet<Address>),
    StopBeforeAnyOf(AHashSet<Address>),
    StopBeforeOr(Address, usize),
    StopAfterOr(Address, usize),
    StopAfterAnyOfOr(AHashSet<Address>, usize),
    StopBeforeAnyOfOr(AHashSet<Address>, usize),
    #[doc(hidden)]
    Reached,
}

impl Display for Bound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "unbounded"),
            Self::Count(steps) => write!(f, "{steps} remaining"),
            Self::StopBefore(addr) => write!(f, "stopping when {addr} reached"),
            Self::StopBeforeAnyOf(addrs) => write!(f, "stopping when one of {:?} reached", addrs),
            Self::StopAfter(addr) => write!(f, "stopping after {addr} reached"),
            Self::StopAfterAnyOf(addrs) => write!(f, "stopping after one of {:?} reached", addrs),
            Self::StopBeforeOr(addr, steps) => {
                write!(f, "stopping when {addr} reached or after {steps}")
            }
            Self::StopBeforeAnyOfOr(addrs, steps) => {
                write!(f, "stopping when one of {addrs:?} reached or after {steps}")
            }
            Self::StopAfterOr(addr, steps) => {
                write!(f, "stopping after {addr} reached or after {steps}")
            }
            Self::StopAfterAnyOfOr(addrs, steps) => write!(
                f,
                "stopping after one of {addrs:?} reached or after {steps}"
            ),
            Self::Reached => write!(f, "reached"),
        }
    }
}

impl Bound {
    pub fn should_continue(&mut self, at: Address) -> bool {
        match self {
            Bound::None => true,
            Bound::Count(ref mut n) => {
                if *n > 0 {
                    *n -= 1;
                    true
                } else {
                    *self = Self::Reached;
                    false
                }
            }
            Bound::StopBefore(addr) => {
                if *addr == at {
                    *self = Self::Reached;
                    false
                } else {
                    true
                }
            }
            Bound::StopBeforeAnyOf(addrs) => {
                if addrs.contains(&at) {
                    *self = Self::Reached;
                    false
                } else {
                    true
                }
            }
            Bound::StopAfter(addr) => {
                if *addr == at {
                    *self = Self::Reached;
                    true
                } else {
                    true
                }
            }
            Bound::StopAfterAnyOf(addrs) => {
                if addrs.contains(&at) {
                    *self = Self::Reached;
                    true
                } else {
                    true
                }
            }
            Bound::StopBeforeOr(addr, ref mut n) => {
                if *addr == at || *n == 0 {
                    *self = Self::Reached;
                    false
                } else {
                    *n -= 1;
                    true
                }
            }
            Bound::StopBeforeAnyOfOr(addrs, ref mut n) => {
                if addrs.contains(&at) || *n == 0 {
                    *self = Self::Reached;
                    false
                } else {
                    *n -= 1;
                    true
                }
            }
            Bound::StopAfterOr(addr, ref mut n) => {
                if *addr == at || *n == 0 {
                    *self = Self::Reached;
                    true
                } else {
                    *n -= 1;
                    true
                }
            }
            Bound::StopAfterAnyOfOr(addrs, ref mut n) => {
                if addrs.contains(&at) || *n == 0 {
                    *self = Self::Reached;
                    true
                } else {
                    *n -= 1;
                    true
                }
            }
            Bound::Reached => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Configuration {
    pub ignore_invalid_accesses: bool,
    pub ignore_invalid_branches: bool,
    pub ignore_unimplemented_ops: bool,
    pub ignore_divide_by_zero: bool,
    pub ignore_zero_region: bool,
    pub ignore_failures: bool,
    pub ignore_calls: bool,

    pub treat_branches_via_pc_as_calls: bool,

    pub enable_injections: bool,
    pub enable_external_injections: bool,

    pub enable_restores: bool,
    pub preserve_tracked_on_strategy_restore: bool,

    pub single_function_analysis: bool,

    pub track_accesses_all: bool,
    pub track_accesses_any: AHashSet<Location>,
    pub track_invalid: bool,

    pub stack_start: Address,
    pub stack_base: Address,
    pub stack_size: usize,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            ignore_invalid_accesses: true,
            ignore_invalid_branches: false,
            ignore_unimplemented_ops: false,
            ignore_divide_by_zero: false,
            ignore_zero_region: true,
            ignore_failures: false,
            ignore_calls: false,

            treat_branches_via_pc_as_calls: true,

            // enables regular injections (values, fixups, redirects)
            enable_injections: true,
            // enables regular injections and externs
            enable_external_injections: false,

            enable_restores: false,
            preserve_tracked_on_strategy_restore: false,

            single_function_analysis: false,

            track_accesses_all: false,
            track_accesses_any: AHashSet::default(),
            track_invalid: false,

            stack_start: Address::from(0x7ffe_f000u32),
            stack_base: Address::from(0x7ffe_0000u32),
            stack_size: 0x10000,
        }
    }
}

pub type IREvalConfig = Configuration;

#[derive(Default)]
pub struct ObserverContext<'a> {
    mapping: AHashMap<uuid::Uuid, ObserverId>,
    context: Vec<Option<Box<dyn AnyLifetime<'a>>>>,
}

pub trait ObserverState<'a>: AnyLifetime<'a> {
    fn id(&self) -> &uuid::Uuid;
}

impl<'a> ObserverContext<'a> {
    pub fn get<S>(&self, id: uuid::Uuid) -> Option<&S>
    where
        S: ObserverState<'a>,
    {
        self.mapping
            .get(&id)
            .and_then(|id| self.context.get(id.index()))
            .and_then(|st| st.as_ref())
            .and_then(|st| st.downcast_ref::<S>())
    }

    pub fn get_mut<S>(&mut self, id: uuid::Uuid) -> Option<&mut S>
    where
        S: ObserverState<'a>,
    {
        self.mapping
            .get(&id)
            .and_then(|id| self.context.get_mut(id.index()))
            .and_then(|st| st.as_mut())
            .and_then(|st| st.downcast_mut::<S>())
    }

    pub fn set<S>(&mut self, id: uuid::Uuid, state: S)
    where
        S: ObserverState<'a>,
    {
        let id = *self
            .mapping
            .entry(id)
            .or_insert(ObserverId::from(self.context.len()));
        if id.index() == self.context.len() {
            self.context.push(Some(Box::new(state)));
        } else {
            self.context[id.index()] = Some(Box::new(state));
        }
    }
}

pub struct IREvaluator {
    config: Configuration,
    context: Box<dyn IRContext>,
    restore: Option<Box<dyn Any>>,
    tracked: Vec<Access>,
    observers: Vec<Box<dyn Observer>>,
    max_address: Address,
}

impl IREvaluator {
    pub fn new_with<'a, C, P>(context: C, mut config: Configuration) -> Result<Self, Error>
    where
        C: Into<ProjectContext<'a, P>>,
        P: InsnTable + 'a,
    {
        let context = context.into();

        // validate stack configuration
        let stack_last = config.stack_base + config.stack_size;
        if stack_last <= config.stack_base {
            return Err(Error::Configuration("invalid stack bounds"));
        }

        let stack = config.stack_base..stack_last;
        if !stack.contains(&config.stack_start) {
            return Err(Error::Configuration("stack start is not a stack address"));
        }

        let translator = context.lifter.translator();
        let convention = context.lifter.convention();
        let space = translator.manager().default_space();
        let max_address = Address::from(
            1u64.checked_shl(context.lifter.address_bits())
                .unwrap_or(0)
                .wrapping_sub(1),
        );

        let mut backing = Vec::with_capacity(
            context
                .memory
                .regions()
                .iter(..)
                .map(|(_, r)| r.bytes().len())
                .sum(),
        );

        let ivt = context
            .memory
            .regions()
            .iter(..)
            .filter_map(|(iv, r)| {
                if config.ignore_zero_region && iv.contains(&Address::from(0u64)) {
                    None
                } else {
                    let iv = iv.start..iv.end;
                    let loaded = LoadedSegment::new(r.name(), backing.len());
                    backing.extend_from_slice(r.bytes());
                    Some((iv.clone(), loaded))
                }
            })
            .collect::<Vec<_>>();

        let flat = FlatState::from_vec(space, backing);
        let mut state = PagedState::from_parts(ivt.into_iter(), flat);

        // validate stack does not overlap with any mapped regions
        for mapping in state.mappings() {
            let base = mapping.base_address();
            let mapping_iv = base..base + mapping.len();

            if stack.contains(&mapping_iv.start) || stack.contains(&(mapping_iv.end - 1usize)) {
                return Err(Error::Configuration("stack overlaps with mapped region"));
            }
        }

        state
            .static_mapping("stack", config.stack_base, config.stack_size)
            .map_err(|_| Error::Configuration("could not create stack"))?;

        let mut context = if translator.is_big_endian() {
            let context = PCodeState::<_, BE>::new(state, translator, convention);
            Box::new(context) as Box<dyn IRContext>
        } else {
            let context = PCodeState::<_, LE>::new(state, translator, convention);
            Box::new(context) as Box<dyn IRContext>
        };

        context.write_stack_pointer(config.stack_start)?;

        let restore = if config.enable_restores {
            Some(context.freeze())
        } else {
            None
        };

        if config.single_function_analysis {
            config.ignore_calls = true;
        }

        Ok(Self {
            context,
            restore,
            config,
            tracked: Default::default(),
            observers: Default::default(),
            max_address,
        })
    }

    pub fn static_mapping<N, A>(&mut self, name: N, base: A, size: usize) -> Result<Address, Error>
    where
        A: Into<Option<Address>>,
        N: Borrow<str>,
    {
        let base = if let Some(base) = base.into() {
            base
        } else {
            self.find_free_region(size)
                .ok_or_else(|| Error::NoFreeSpace(size))?
        };

        let last = base + size;
        if last <= base {
            return Err(Error::Configuration("invalid mapping bounds"));
        }

        let new_mapping = base..last;
        if !self.is_free_region(&new_mapping) {
            return Err(Error::Configuration(
                "mapping overlaps with existing region",
            ));
        }

        self.context
            .memory_mut()
            .static_mapping(name.borrow(), base, size)
            .map_err(|_| Error::Configuration("could not create mapping"))?;

        Ok(base)
    }

    pub fn mapped_regions<'a>(&'a self) -> impl Iterator<Item = Range<Address>> + 'a {
        self.context
            .memory()
            .segments()
            .intervals(..)
            .chain(self.context.memory().mappings().map(|m| {
                let base = m.base_address();
                base..base + m.len()
            }))
            .sorted_by_key(|iv| iv.start)
    }

    pub fn free_regions<'a>(&'a self) -> impl Iterator<Item = Range<Address>> + 'a {
        let mut last = Address::from(0u32);

        self.mapped_regions()
            .with_position()
            .map(move |iv| match iv {
                (Position::First | Position::Middle, iv) => {
                    let res = if iv.start > last {
                        [Some(last..iv.start), None].into_iter()
                    } else {
                        [None, None].into_iter()
                    };
                    last = iv.end;
                    res
                }
                (Position::Last | Position::Only, iv) => {
                    let p1 = if iv.start > last {
                        Some(last..iv.start)
                    } else {
                        None
                    };

                    let p2 = if iv.end < self.max_address {
                        Some(iv.end..self.max_address)
                    } else {
                        None
                    };

                    [p1, p2].into_iter()
                }
            })
            .flatten()
            .filter_map(|iv| iv)
    }

    fn is_free_region(&self, range: &Range<Address>) -> bool {
        !self
            .mapped_regions()
            .any(|m| range.contains(&m.start) || range.contains(&(m.end - 1usize)))
    }

    fn find_free_region(&self, size: usize) -> Option<Address> {
        self.free_regions().find_map(|iv| {
            let nstart = if self.config.ignore_zero_region && iv.start == Address::from(0u32) {
                iv.start + 0x1000usize
            } else {
                iv.start
            };

            let align = u64::from(self.max_address).count_ones() as u64 / 8;
            let nalign = nstart + (align - u64::from(nstart) % align);

            if nalign > iv.end || nalign < iv.start {
                return None;
            }

            if usize::from(iv.end - nalign) >= size {
                Some(nalign)
            } else {
                None
            }
        })
    }

    pub fn configuration(&self) -> &Configuration {
        &self.config
    }

    pub fn configuration_mut(&mut self) -> &mut Configuration {
        &mut self.config
    }

    pub fn refreeze(&mut self) -> Option<Box<dyn Any>> {
        self.refreeze_with(None)
    }

    pub fn refreeze_with(&mut self, with: Option<Box<dyn Any>>) -> Option<Box<dyn Any>> {
        self.config.enable_restores = true;
        self.restore.replace(if let Some(frozen) = with {
            frozen
        } else {
            self.context.freeze()
        })
    }

    pub fn restore(&mut self) -> Result<(), Error> {
        for observer in self.observers.iter_mut() {
            observer.restore()?;
        }

        if let Some(old) = self.restore.as_ref() {
            self.context.restore(old);
            self.tracked.clear();
            Ok(())
        } else {
            Err(Error::UnsupportedRestore)
        }
    }

    pub fn track_location(&mut self, loc: Location) {
        if !self.config.track_accesses_all {
            self.config.track_accesses_any.insert(loc);
        }
    }

    pub fn tracked(&self) -> &[Access] {
        &self.tracked
    }

    pub fn stack_base(&self) -> Address {
        self.config.stack_base
    }

    pub fn stack_limit(&self) -> Address {
        self.config.stack_base + self.config.stack_size
    }

    pub fn stack(&self) -> Result<(Address, &[u8]), Error> {
        let addr = self.context.read_stack_pointer()?;
        let bytes = self
            .context
            .read_bytes(self.config.stack_base, self.config.stack_size)?;

        Ok((addr, bytes))
    }

    pub fn is_stack_var(&self, var: &Var) -> bool {
        if let Some(addr) = var.address() {
            addr >= self.stack_base() && addr < self.stack_limit()
        } else {
            false
        }
    }

    pub fn context(&self) -> &Box<dyn IRContext> {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut Box<dyn IRContext> {
        &mut self.context
    }

    pub fn register_observer<O: Observer + 'static>(&mut self, observer: O) -> ObserverId {
        let id = self.observers.len();
        self.observers.push(Box::new(observer));
        ObserverId::from(id)
    }

    pub fn get_observer<O: Observer>(&self, id: ObserverId) -> Option<&O> {
        self.observers
            .get(id.index())
            .and_then(|o| o.downcast_ref::<O>())
    }

    pub fn get_observer_mut<O: Observer>(&mut self, id: ObserverId) -> Option<&mut O> {
        self.observers
            .get_mut(id.index())
            .and_then(|o| o.downcast_mut::<O>())
    }

    pub fn unregister_observers(&mut self) -> Vec<Box<dyn Observer>> {
        std::mem::take(&mut self.observers)
    }

    fn observe_pre_var_read(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        var: &Var,
    ) -> Result<(), ObserverError> {
        for observer in self.observers.iter_mut() {
            observer.observe_pre_var_read_with(&mut self.context, observer_context, loc, var)?;
        }
        Ok(())
    }

    fn observe_post_var_read(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        var: &Var,
        val: &mut BitVec,
    ) -> Result<(), ObserverError> {
        for observer in self.observers.iter_mut() {
            observer.observe_post_var_read_with(
                &mut self.context,
                observer_context,
                loc,
                var,
                val,
            )?;
        }
        Ok(())
    }

    fn observe_post_var_invalid_read(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        var: &Var,
        val: &mut Option<BitVec>,
    ) -> Result<(), ObserverError> {
        for observer in self.observers.iter_mut() {
            observer.observe_post_var_invalid_read_with(
                &mut self.context,
                observer_context,
                loc,
                var,
                val,
            )?;
        }
        Ok(())
    }

    fn observe_pre_var_write(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        var: &Var,
        val: &mut BitVec,
        sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        for observer in self.observers.iter_mut() {
            observer.observe_pre_var_write_with(
                &mut self.context,
                observer_context,
                loc,
                var,
                val,
                sexpr,
            )?;
        }
        Ok(())
    }

    fn observe_post_var_write(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        var: &Var,
        val: &BitVec,
        sexpr: &Term<Expr>,
    ) -> Result<(), ObserverError> {
        for observer in self.observers.iter_mut() {
            observer.observe_post_var_write_with(
                &mut self.context,
                observer_context,
                loc,
                var,
                val,
                sexpr,
            )?;
        }
        Ok(())
    }

    fn observe_pre_cbranch(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        cond: &Term<Expr>,
        cval: &mut BitVec,
    ) -> Result<(), ObserverError> {
        for observer in self.observers.iter_mut() {
            observer.observe_pre_cbranch_with(
                &mut self.context,
                observer_context,
                loc,
                cond,
                cval,
            )?;
        }
        Ok(())
    }

    fn observe_insn(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        insn: &Term<Insn>,
    ) -> Result<bool, ObserverError> {
        let mut skip = false;
        for observer in self.observers.iter_mut() {
            skip |= observer.observe_insn_with(&mut self.context, observer_context, loc, insn)?;
        }
        Ok(skip)
    }

    fn override_insn<'a>(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        insn: &'a Term<Insn>,
    ) -> Result<Cow<'a, Term<Insn>>, ObserverError> {
        let mut insn = Cow::Borrowed(insn);
        for observer in self.observers.iter_mut() {
            observer.override_insn_with(&mut self.context, observer_context, loc, &mut insn)?;
        }
        Ok(insn)
    }

    fn observe_stmt(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        stmt: &Term<Stmt>,
    ) -> Result<bool, ObserverError> {
        let mut skip = false;
        for observer in self.observers.iter_mut() {
            skip |= observer.observe_stmt_with(&mut self.context, observer_context, loc, stmt)?;
        }
        Ok(skip)
    }

    fn observe_pre_branch(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        target: Location,
    ) -> Result<(), ObserverError> {
        for observer in self.observers.iter_mut() {
            observer.observe_pre_branch_with(&mut self.context, observer_context, loc, target)?;
        }
        Ok(())
    }

    fn observe_pre_call(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        target: Address,
    ) -> Result<(), ObserverError> {
        for observer in self.observers.iter_mut() {
            observer.observe_pre_call_with(&mut self.context, observer_context, loc, target)?;
        }
        Ok(())
    }

    fn observe_external<'a, P>(
        &mut self,
        context: ProjectContext<'a, P>,
        observer_context: &mut ObserverContext,
        loc: Location,
        target: FunctionSummaryId,
    ) -> Result<bool, ObserverError>
    where
        P: InsnTable + 'a,
    {
        let mut handled = false;
        if let Some(target) = context.fstable.get(target) {
            for observer in self.observers.iter_mut() {
                handled |= observer.observe_external_with(
                    &mut self.context,
                    observer_context,
                    loc,
                    target,
                    handled,
                )?;
            }
        }
        Ok(handled)
    }

    fn observe_intrinsic(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        name: Ustr,
        arguments: SmallVec<[BitVec; 4]>,
        result: &mut Option<BitVec>,
    ) -> Result<bool, ObserverError> {
        let mut handled = false;
        let mut arguments = arguments;
        for observer in self.observers.iter_mut() {
            handled |= observer.observe_intrinsic_with(
                &mut self.context,
                observer_context,
                loc,
                name,
                arguments.as_mut(),
                result,
                handled,
            )?;
        }
        Ok(handled)
    }

    fn observe_block_entry(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        block: &CodeBlock,
    ) -> Result<(), ObserverError> {
        for observer in self.observers.iter_mut() {
            observer.observe_block_entry_with(&mut self.context, observer_context, loc, block)?;
        }
        Ok(())
    }

    fn observe_block_exit(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        block: &CodeBlock,
    ) -> Result<(), ObserverError> {
        for observer in self.observers.iter_mut() {
            observer.observe_block_exit_with(&mut self.context, observer_context, loc, block)?;
        }
        Ok(())
    }

    fn observe_function_entry(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        function: &Function,
        summary: Option<&FunctionSummary>,
    ) -> Result<(), ObserverError> {
        for observer in self.observers.iter_mut() {
            observer.observe_function_entry_with(
                &mut self.context,
                observer_context,
                loc,
                function,
                summary,
            )?;
        }
        Ok(())
    }

    pub fn eval_with<'a, C, P, S>(
        &mut self,
        context: C,
        from: Address,
        bound: Bound,
        strategy: S,
    ) -> Result<(), Error>
    where
        C: Into<ProjectContext<'a, P>>,
        P: InsnTable + 'a,
        S: Strategy,
    {
        let mut observer_context = ObserverContext::default();
        self.eval_full_with(context, &mut observer_context, from, bound, strategy)
    }

    pub fn eval_full_with<'a, C, P, S>(
        &mut self,
        context: C,
        observer_context: &mut ObserverContext,
        from: Address,
        bound: Bound,
        mut strategy: S,
    ) -> Result<(), Error>
    where
        C: Into<ProjectContext<'a, P>>,
        P: InsnTable + 'a,
        S: Strategy,
    {
        let context = context.into();
        while {
            let mut bound = bound.clone();

            strategy.initialise_path();
            if let Err(err) =
                self.eval_path_full(context, observer_context, from, &mut bound, &mut strategy)
            {
                if !self.config.ignore_failures {
                    return Err(err);
                }
            }
            strategy.terminate_path();

            let done = strategy.fully_explored();

            if !done && self.config.enable_restores {
                if self.config.preserve_tracked_on_strategy_restore {
                    if let Some(old) = self.restore.as_ref() {
                        self.context.restore(old);
                        for observer in self.observers.iter_mut() {
                            observer.restore()?;
                        }
                    } else {
                        return Err(Error::UnsupportedRestore);
                    }
                } else {
                    self.restore()?;
                }
            }

            !done
        } {}

        Ok(())
    }

    pub fn eval<'a, C, P>(
        &mut self,
        context: C,
        from: Address,
        bound: impl BorrowMut<Bound>,
    ) -> Result<Address, Error>
    where
        C: Into<ProjectContext<'a, P>>,
        P: InsnTable + 'a,
    {
        let mut observer_context = ObserverContext::default();
        self.eval_full(context, &mut observer_context, from, bound)
    }

    pub fn eval_full<'a, P, C>(
        &mut self,
        context: C,
        observer_context: &mut ObserverContext,
        from: Address,
        bound: impl BorrowMut<Bound>,
    ) -> Result<Address, Error>
    where
        C: Into<ProjectContext<'a, P>>,
        P: InsnTable + 'a,
    {
        self.eval_path_full(
            context,
            observer_context,
            from,
            bound,
            &mut DefaultStrategy::default(),
        )
    }

    pub fn eval_path<'a, C, P, S>(
        &mut self,
        context: C,
        from: Address,
        bound: impl BorrowMut<Bound>,
        strategy: &mut S,
    ) -> Result<Address, Error>
    where
        C: Into<ProjectContext<'a>>,
        P: InsnTable + 'a,
        S: Strategy,
    {
        let mut observer_context = ObserverContext::default();
        self.eval_path_full(context, &mut observer_context, from, bound, strategy)
    }

    pub fn eval_path_full<'a, C, P, S>(
        &mut self,
        context: C,
        observer_context: &mut ObserverContext,
        from: Address,
        mut bound: impl BorrowMut<Bound>,
        strategy: &mut S,
    ) -> Result<Address, Error>
    where
        C: Into<ProjectContext<'a, P>>,
        P: InsnTable + 'a,
        S: Strategy,
    {
        let context = context.into();
        if !self.config.preserve_tracked_on_strategy_restore {
            self.tracked.clear();
        }

        let mut current_block = None::<&CodeBlock>;
        let mut current_function = None::<&Function>;

        let mut addr = from;
        let bound = bound.borrow_mut();

        self.apply_injections(context.injections.global_values())?;

        while bound.should_continue(addr) {
            tracing::trace!("bound: {bound}");

            let insn = context
                .itable
                .get_at(addr)
                .ok_or_else(|| Error::InvalidInstruction(addr))?;

            tracing::trace!("emulating instruction at {addr}");
            self.context.write_program_counter(addr)?;

            let prev_address = addr;

            if let Some(fcn) = context.ftable.get_point(&addr) {
                if self.config.single_function_analysis
                    && matches!(current_function, Some(cfcn) if cfcn.id() != fcn.id())
                {
                    // moved to a different function
                    break;
                }

                current_function = Some(fcn);

                let location = Location::from(addr);

                // NOTE: we may have an override...
                if let Some(extrn) = self
                    .config
                    .enable_injections
                    .then(|| context.injections.get_function_stub(fcn.id()))
                    .flatten()
                {
                    match extrn {
                        InjectionStub::Redirect(naddr) => {
                            tracing::trace!(
                                "performing redirection via injection from {addr} to {naddr}"
                            );
                            addr = *naddr;
                        }
                        InjectionStub::Extern(extrn) if self.config.enable_external_injections => {
                            let fname = extrn.name();
                            let naddr = extrn.address();

                            tracing::trace!("performing external call via injection from {addr} to {fname} at {naddr}");

                            addr = naddr;
                        }
                        _ => {
                            // NOTE: call fixups are handled via Stmt::Call.
                        }
                    }

                    continue;
                }

                let summary = context.fstable.get_for_function(fcn.id());
                self.observe_function_entry(observer_context, location, fcn, summary)?;
                self.apply_injections(context.injections.function_values(fcn.id()))?;
            }

            if let Some(cb) = context.cbtable.get_point(&addr) {
                let location = Location::from(addr);
                if let Some(oldcb) = current_block.replace(cb) {
                    self.observe_block_exit(observer_context, location, oldcb)?;
                }
                self.observe_block_entry(observer_context, location, cb)?;
                current_block = Some(cb);
            }

            addr = self.eval_insn(context, observer_context, insn, strategy)?;

            // avoid infinite loop
            if addr == prev_address {
                break;
            }
        }

        Ok(addr)
    }

    fn apply_injections<'a>(
        &mut self,
        values: impl Iterator<Item = (&'a InjectionOperand, &'a BitVec)>,
    ) -> Result<(), Error> {
        for (opnd, val) in values {
            match opnd {
                InjectionOperand::Global(addr) => {
                    self.context.write_addr(*addr, val)?;
                }
                InjectionOperand::Register(reg) => {
                    let nbits = reg.nbits();
                    if val.nbits() != nbits {
                        self.context
                            .write_var(&reg, &val.to_owned().cast(nbits as _))?;
                    } else {
                        self.context.write_var(&reg, val)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn eval_stmts_with<'a, S, P>(
        &mut self,
        context: ProjectContext<'a, P>,
        observer_context: &mut ObserverContext,
        location: Location,
        stmts: &[Term<Stmt>],
        strategy: &mut S,
    ) -> Result<Location, Error>
    where
        S: Strategy,
        P: InsnTable + 'a,
    {
        let mut loc = location;

        while loc.address == location.address() && loc.position < stmts.len() {
            let stmt = &stmts[loc.position];

            tracing::trace!(
                "{loc} {}",
                stmt.display_with(Some(context.lifter.translator()))
            );

            match self.eval_stmt(context, observer_context, loc, stmt, strategy) {
                Ok(nloc) => {
                    // if we loop back on self, then we count that as a new insn
                    if loc.address == nloc.address && nloc.position == 0 {
                        return Ok(nloc);
                    }

                    //posn = nposn;

                    if loc.address == nloc.address && loc.position == nloc.position {
                        // avoid infinite loop
                        loc.position = nloc.position + 1;
                    } else {
                        loc = nloc;
                    }
                }
                Err(e) => match e {
                    Error::InvalidAccess(_, var) => {
                        if self.config.ignore_invalid_accesses {
                            tracing::debug!("ignoring invalid access of {var} at {loc}");
                            if self.should_track(loc) {
                                self.track(loc, AccessKind::Invalid, var)
                            }
                            loc.position += 1;
                        } else {
                            return Err(e);
                        }
                    }
                    Error::DivideByZero(_) => {
                        if self.config.ignore_divide_by_zero {
                            tracing::debug!("ignoring divide by zero at {loc}");
                            loc.position += 1;
                        } else {
                            return Err(e);
                        }
                    }
                    Error::UnsupportedCast(_) => {
                        if self.config.ignore_divide_by_zero {
                            tracing::debug!("ignoring unsupported cast at {loc}");
                            loc.position += 1;
                        } else {
                            return Err(e);
                        }
                    }
                    Error::UnimplementedOp(_) => {
                        if self.config.ignore_unimplemented_ops {
                            tracing::debug!("ignoring unimplemented operator at {loc}");
                            loc.position += 1;
                        } else {
                            return Err(e);
                        }
                    }
                    _ => return Err(e),
                },
            }
        }

        Ok(loc)
    }

    fn eval_insn<'a, S, P>(
        &mut self,
        context: ProjectContext<'a, P>,
        observer_context: &mut ObserverContext,
        insn: &Term<Insn>,
        strategy: &mut S,
    ) -> Result<Address, Error>
    where
        S: Strategy,
        P: InsnTable + 'a,
    {
        let mut loc = Location::new(insn.address(), 0);

        let insn = self.override_insn(observer_context, loc, insn)?;

        loc = Location::new(insn.address(), 0);

        if self.observe_insn(observer_context, loc, &*insn)? {
            // skip
            return Ok(insn.next_address());
        }

        let stmts = insn.operations();

        let nloc = self.eval_stmts_with(context, observer_context, loc, stmts, strategy)?;

        if nloc == loc {
            // propagate case where we hit the instruction start
            Ok(nloc.address())
        } else if nloc.address != insn.address() {
            // case where we branch
            tracing::trace!("branching to {}", nloc.address);
            Ok(nloc.address)
        } else {
            // case where we fall-through
            Ok(insn.next_address())
        }
    }

    fn eval_stmt<'a, S, P>(
        &mut self,
        context: ProjectContext<'a, P>,
        observer_context: &mut ObserverContext,
        loc: Location,
        stmt: &Term<Stmt>,
        strategy: &mut S,
    ) -> Result<Location, Error>
    where
        S: Strategy,
        P: InsnTable + 'a,
    {
        if self.observe_stmt(observer_context, loc, stmt)? {
            return Ok(loc + 1);
        }

        match stmt.value() {
            Stmt::Assign(var, expr) => {
                let mut val = self.eval_expr(context, observer_context, loc, expr)?;
                self.write_var(observer_context, loc, var, &mut val, expr)
                    .map_err(|_| Error::InvalidAccess(loc, *var))?;
            }
            Stmt::Store(dst, src, bits, spc) => {
                let mut sval = self.eval_expr(context, observer_context, loc, src)?;
                let dval = self.eval_expr(context, observer_context, loc, dst)?;

                debug_assert!(sval.nbits() == *bits);

                let space = context.lifter.translator().manager().space_by_id(*spc);

                let doff = dval.to_u64().ok_or_else(|| Error::InvalidAddess(loc))?;
                let dvar = Var::new(space, doff, *bits, 0);

                self.write_var(observer_context, loc, &dvar, &mut sval, src)
                    .map_err(|_| Error::InvalidAccess(loc, dvar))?;
            }
            Stmt::CBranch(cond, br) => {
                let mut cval = self.eval_expr(context, observer_context, loc, cond)?;

                self.observe_pre_cbranch(observer_context, loc, cond, &mut cval)?;

                let sval = strategy.branch_path(PredicatedLocation::new(loc, !cval.is_zero()));
                if sval {
                    let ret = self.eval_branch(context, observer_context, loc, br)?;
                    return Ok(
                        if self.config.ignore_invalid_branches
                            && !context.itable.contains(ret.address)
                        {
                            loc + 1
                        } else {
                            ret
                        },
                    );
                }
            }
            Stmt::Branch(br) => {
                if self.config.treat_branches_via_pc_as_calls
                    && *br == BranchTarget::computed(Expr::from(context.lifter.program_counter()))
                {
                    if !self.config.ignore_calls {
                        let ret = self.eval_branch(context, observer_context, loc, br)?;

                        self.observe_pre_call(observer_context, loc, ret.address)?;

                        return Ok(
                            if self.config.ignore_invalid_branches
                                && !context.itable.contains(ret.address)
                            {
                                let sp = self.context.read_stack_pointer()?;
                                self.context.write_stack_pointer(
                                    sp + context
                                        .lifter
                                        .convention()
                                        .default_prototype()
                                        .extra_pop(),
                                )?;
                                loc + 1
                            } else {
                                ret
                            },
                        );
                    } else {
                        // should we apply stack extra pop by default?
                        return Ok(loc + 1);
                    }
                } else {
                    let ret = self.eval_branch(context, observer_context, loc, br)?;

                    self.observe_pre_branch(observer_context, loc, ret)?;

                    return Ok(
                        if self.config.ignore_invalid_branches
                            && !context.itable.contains(ret.address)
                        {
                            loc + 1
                        } else {
                            ret
                        },
                    );
                }
            }
            Stmt::Return(br) => {
                let ret = self.eval_branch(context, observer_context, loc, br)?;
                return Ok(
                    if self.config.ignore_invalid_branches && !context.itable.contains(ret.address)
                    {
                        loc + 1
                    } else {
                        ret
                    },
                );
            }
            Stmt::Call(br, _) => {
                if self.config.ignore_calls {
                    // should we apply stack extra pop by default?
                    return Ok(loc + 1);
                }

                let ret = self.eval_branch(context, observer_context, loc, br)?;
                self.observe_pre_call(observer_context, loc, ret.address)?;

                if self.config.ignore_invalid_branches && !context.itable.contains(ret.address) {
                    let sp = self.context.read_stack_pointer()?;
                    self.context.write_stack_pointer(
                        sp + context.lifter.convention().default_prototype().extra_pop(),
                    )?;
                    return Ok(loc + 1);
                }

                if !self.config.enable_injections {
                    return Ok(ret);
                }

                let Some(fixup) = context
                    .ftable
                    .get_point(&ret.address())
                    .and_then(|f| context.injections.get_function_stub(f.id())?.fixup())
                else {
                    return Ok(ret);
                };

                let name = fixup.name();
                let addr = ret.address();

                tracing::trace!("performing fixup via injection at {addr} to {name}");

                // NOTE: we apply a default strategy
                self.eval_stmts_with(
                    context,
                    observer_context,
                    ret,
                    fixup.operations(),
                    &mut DefaultStrategy,
                )?;

                // NOTE: fixups should return to the next instruction (a call skip)
                return Ok(loc + 1);
            }
            Stmt::Intrinsic(name, args) => {
                let mut result = None;
                let args = args
                    .iter()
                    .map(|expr| self.eval_expr(context, observer_context, loc, expr))
                    .collect::<Result<_, _>>()?;
                if !self.observe_intrinsic(observer_context, loc, *name, args, &mut result)? {
                    tracing::debug!("{loc} skipping intrinsic {name}");
                }
            }
            Stmt::PointerHint(_) | Stmt::Skip => {}
        }

        // default is to fall through
        Ok(loc + 1)
    }

    fn track(&mut self, loc: Location, kind: AccessKind, var: Var) {
        if kind.is_valid() || self.config.track_invalid {
            self.tracked.push(Access {
                location: loc,
                kind,
                variable: var,
            })
        }
    }

    fn should_track(&self, loc: Location) -> bool {
        self.config.track_accesses_all || self.config.track_accesses_any.contains(&loc)
    }

    fn eval_branch<'a, P>(
        &mut self,
        context: ProjectContext<'a, P>,
        observer_context: &mut ObserverContext,
        loc: Location,
        branch: &Term<BranchTarget>,
    ) -> Result<Location, Error>
    where
        P: InsnTable + 'a,
    {
        let nloc = match branch.value() {
            BranchTarget::External(_, id) => {
                return if self.observe_external(context, observer_context, loc, *id)?
                    || self.config.ignore_invalid_branches
                {
                    Ok(loc + 1)
                } else {
                    Err(Error::UnhandledExternal(loc.address, *id))
                }
            }
            BranchTarget::Location(nloc) => *nloc,
            BranchTarget::Computed(expr) => {
                let tgt = self
                    .eval_expr(context, observer_context, loc, expr)?
                    .to_u64()
                    .ok_or_else(|| Error::InvalidAddess(loc))?;

                let taddr = Address::new(context.lifter.global_space(), tgt);
                Location::from(taddr)
            }
        };

        if self.should_track(loc) {
            self.track(
                loc,
                AccessKind::Branch(nloc.position),
                Var::new(
                    context.lifter.global_space(),
                    nloc.address.into(),
                    context.lifter.global_space().address_size() as u32 * 8,
                    0,
                ),
            )
        }

        Ok(nloc)
    }

    fn eval_cast<'a, P>(
        &self,
        _context: ProjectContext<'a, P>,
        _observer_context: &mut ObserverContext,
        loc: Location,
        from: BitVec,
        to: &Term<Type>,
    ) -> Result<BitVec, Error>
    where
        P: InsnTable + 'a,
    {
        if to.is_bool() {
            return Ok(if from.is_zero() {
                BitVec::zero(8)
            } else {
                BitVec::one(8)
            });
        }

        if to.is_float() {
            tracing::debug!("{} cast from {} to float unsupported", loc, from);
            return Err(Error::UnsupportedCast(loc));
        }

        let tbits = to.nbits();

        if tbits == 0 {
            tracing::error!("{} cast from {} to zero sized type {}", loc, from, to);
            return Err(Error::UnsupportedCast(loc));
        }

        let tsign = to.is_signed();

        let fbits = from.nbits();
        let fsign = from.is_signed();

        if fbits == tbits && fsign == tsign {
            // no-op
            Ok(from)
        } else if tsign {
            // signed cast
            Ok(from.signed().cast(tbits as usize))
        } else {
            // unsigned cast
            Ok(from.unsigned().cast(tbits as usize))
        }
    }

    fn eval_expr<'a, P>(
        &mut self,
        context: ProjectContext<'a, P>,
        observer_context: &mut ObserverContext,
        loc: Location,
        expr: &Term<Expr>,
    ) -> Result<BitVec, Error>
    where
        P: InsnTable + 'a,
    {
        match expr.value() {
            Expr::Var(var) => self.read_var(observer_context, loc, var),
            Expr::Val(val, _) => Ok(val.clone()),
            Expr::Cast(expr, to) => {
                let from = self.eval_expr(context, observer_context, loc, expr)?;
                self.eval_cast(context, observer_context, loc, from, to)
            }
            Expr::Load(expr, bits, spc) => {
                let soff = self
                    .eval_expr(context, observer_context, loc, expr)?
                    .to_u64()
                    .ok_or_else(|| Error::InvalidAddess(loc))?;
                let space = context.lifter.translator().manager().space_by_id(*spc);
                let svar = Var::new(space, soff, *bits, 0);

                self.read_var(observer_context, loc, &svar)
            }
            Expr::UnOp(op, expr) => {
                let val = self.eval_expr(context, observer_context, loc, expr)?;
                match op {
                    UnOp::NEG => Ok(val.neg()),
                    UnOp::NOT => {
                        if expr.is_bool() {
                            Ok(val.not() & BitVec::one(8))
                        } else {
                            Ok(val.not())
                        }
                    }
                    UnOp::POPCOUNT(bits) => Ok(BitVec::from_u32(val.count_ones(), *bits as usize)),
                    _ => {
                        tracing::debug!("{} operation {:?} on {} unsupported", loc, op, val);
                        Err(Error::UnimplementedOp(loc))
                    }
                }
            }
            Expr::UnRel(op, _expr) => {
                // NOTE: only UnRel operation is for FP
                tracing::debug!("{} operation {:?} unsupported", loc, op);
                Err(Error::UnimplementedOp(loc))
            }
            Expr::BinOp(op, lexpr, rexpr) => {
                let lval = self.eval_expr(context, observer_context, loc, lexpr)?;
                let rval = self.eval_expr(context, observer_context, loc, rexpr)?;

                match op {
                    BinOp::AND => Ok(lval & rval),
                    BinOp::OR => Ok(lval | rval),
                    BinOp::XOR => Ok(lval ^ rval),
                    BinOp::ADD => Ok(lval + rval),
                    BinOp::SUB => Ok(lval - rval),
                    BinOp::MUL => Ok(lval * rval),
                    BinOp::SHL => Ok(lval << rval),
                    BinOp::SHR => Ok(lval >> rval),
                    BinOp::SAR => Ok(lval.signed() >> rval.signed()),
                    BinOp::DIV => {
                        if rval.is_zero() {
                            tracing::debug!("{} attempt to divide {} by zero", loc, lval);
                            Err(Error::DivideByZero(loc))
                        } else {
                            Ok(lval / rval)
                        }
                    }
                    BinOp::SDIV => {
                        if rval.is_zero() {
                            tracing::debug!("{} attempt to divide {} by zero", loc, lval);
                            Err(Error::DivideByZero(loc))
                        } else {
                            Ok(lval.signed() / rval.signed())
                        }
                    }
                    BinOp::REM => {
                        if rval.is_zero() {
                            tracing::debug!("{} attempt to divide {} by zero", loc, lval);
                            Err(Error::DivideByZero(loc))
                        } else {
                            Ok(lval % rval)
                        }
                    }
                    BinOp::SREM => {
                        if rval.is_zero() {
                            tracing::debug!("{} attempt to divide {} by zero", loc, lval);
                            Err(Error::DivideByZero(loc))
                        } else {
                            Ok(lval.signed() % rval.signed())
                        }
                    }
                }
            }
            Expr::BinRel(op, lexpr, rexpr) => {
                let lval = self.eval_expr(context, observer_context, loc, lexpr)?;
                let rval = self.eval_expr(context, observer_context, loc, rexpr)?;

                let as_bool = |v: bool| if v { BitVec::one(8) } else { BitVec::zero(8) };

                Ok(as_bool(match op {
                    BinRel::EQ => lval == rval,
                    BinRel::NEQ => lval != rval,
                    BinRel::LT => lval < rval,
                    BinRel::LE => lval <= rval,
                    BinRel::SLT => lval.signed() < rval.signed(),
                    BinRel::SLE => lval.signed() <= rval.signed(),
                    BinRel::SBORROW => lval.signed_borrow(&rval),
                    BinRel::CARRY => lval.carry(&rval),
                    BinRel::SCARRY => lval.signed_carry(&rval),
                }))
            }
            Expr::Choice(sel, choices, default, _) => {
                let selv = self.eval_expr(context, observer_context, loc, sel)?;
                if let Some(choice) = choices
                    .binary_search_by(|(lk, _)| lk.cmp(&selv))
                    .ok()
                    .map(|idx| &choices[idx].1)
                {
                    self.eval_expr(context, observer_context, loc, choice)
                } else if let Some(default) = default {
                    self.eval_expr(context, observer_context, loc, default)
                } else {
                    Err(Error::NoViableChoice(expr.clone()))
                }
            }
            Expr::IfElse(cond, texpr, fexpr) => {
                if self
                    .eval_expr(context, observer_context, loc, cond)?
                    .is_zero()
                {
                    self.eval_expr(context, observer_context, loc, fexpr)
                } else {
                    self.eval_expr(context, observer_context, loc, texpr)
                }
            }
            Expr::Concat(lexpr, rexpr) => {
                let lval = self.eval_expr(context, observer_context, loc, lexpr)?;
                let rval = self.eval_expr(context, observer_context, loc, rexpr)?;

                let tbits = lval.nbits() + rval.nbits();
                let sbits = rval.nbits();

                let lvex = lval.unsigned().cast(tbits as usize) << sbits;
                let rvex = rval.unsigned().cast(tbits as usize);

                Ok(lvex | rvex)
            }
            Expr::Extract(expr, lsb, msb) => {
                let val = self.eval_expr(context, observer_context, loc, expr)?;

                if (msb - lsb) == val.nbits() {
                    Ok(val)
                } else {
                    Ok(if *lsb > 0 {
                        (val >> *lsb).unsigned().cast((msb - lsb) as usize)
                    } else {
                        val.unsigned().cast((msb - lsb) as usize)
                    })
                }
            }
            Expr::ExtractHigh(expr, bits) => {
                let val = self.eval_expr(context, observer_context, loc, expr)?;
                let vbits = val.nbits();

                if vbits > *bits {
                    Ok((val.unsigned() >> (vbits - bits)).cast(*bits as usize))
                } else {
                    Ok(val.unsigned().cast(*bits as usize))
                }
            }
            Expr::ExtractLow(expr, bits) => {
                let val = self.eval_expr(context, observer_context, loc, expr)?;

                Ok(val.unsigned().cast(*bits as usize))
            }
            Expr::Intrinsic(name, args, _) => {
                let mut result = None;
                let args = args
                    .iter()
                    .map(|expr| self.eval_expr(context, observer_context, loc, expr))
                    .collect::<Result<_, _>>()?;
                if !self.observe_intrinsic(observer_context, loc, *name, args, &mut result)? {
                    tracing::debug!("{} unimplemented intrinsic {}", loc, name);
                    Err(Error::UnimplementedOp(loc))
                } else {
                    result.ok_or_else(|| {
                        tracing::debug!("{} unimplemented intrinsic {}", loc, name);
                        Error::UnimplementedOp(loc)
                    })
                }
            }
        }
    }

    fn read_var(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        var: &Var,
    ) -> Result<BitVec, Error> {
        self.observe_pre_var_read(observer_context, loc, var)?;

        let val = self
            .context
            .read_var(var)
            .map_err(|_| Error::InvalidAccess(loc, *var));

        let val = match val {
            Ok(mut val) => {
                self.observe_post_var_read(observer_context, loc, var, &mut val)?;
                val
            }
            Err(err) => {
                let mut nval = None;
                self.observe_post_var_invalid_read(observer_context, loc, var, &mut nval)?;

                if let Some(nval) = nval {
                    nval
                } else {
                    return Err(err);
                }
            }
        };

        if self.should_track(loc) {
            self.track(loc, AccessKind::Load(val.clone()), *var);
        }

        Ok(val)
    }

    fn write_var(
        &mut self,
        observer_context: &mut ObserverContext,
        loc: Location,
        var: &Var,
        val: &mut BitVec,
        sexpr: &Term<Expr>,
    ) -> Result<(), Error> {
        self.observe_pre_var_write(observer_context, loc, var, val, sexpr)?;

        tracing::trace!("write {val:x} to {var}");

        self.context
            .write_var(var, val)
            .map_err(|_| Error::InvalidAccess(loc, *var))?;

        self.observe_post_var_write(observer_context, loc, var, val, sexpr)?;

        if self.should_track(loc) {
            self.track(loc, AccessKind::Store(val.clone()), *var);
        }

        Ok(())
    }
}
