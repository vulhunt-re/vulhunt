use std::marker::PhantomData;

use fugue::bytes::{ByteCast, ByteOrder};
use fugue::lifter::runtime::convention::{Convention, PrototypeOperand};
use fugue::lifter::runtime::language::Language;
use fugue::lifter::runtime::pcode::Varnode;
use fugue::sleigh::language::spaces::AddressSpaceId;
use thiserror::Error;

use crate::eval::state::paged::{self, PagedState};
use crate::eval::state::register::{self, RegisterState};
use crate::eval::state::traits::{State, StateOps};
use crate::eval::state::unique::{self, UniqueState};
use crate::ir::Address;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Memory(paged::Error),
    #[error(transparent)]
    Register(register::Error),
    #[error(transparent)]
    Temporary(unique::Error),
    #[error("unsupported address size of `{0}` bytes")]
    UnsupportedAddressSize(usize),
    #[error("unsupported prototype operand {0:?}")]
    UnsupportedOperand(PrototypeOperand),
}

impl Error {
    pub fn unsupported_address_size(size: usize) -> Self {
        Self::UnsupportedAddressSize(size)
    }

    pub fn unsupported_operand(operand: PrototypeOperand) -> Self {
        Self::UnsupportedOperand(operand)
    }
}

#[derive(Clone, Copy)]
enum PointerSize {
    U8,
    U16,
    U32,
    U64,
}

impl PointerSize {
    fn new(size: usize) -> Result<Self, Error> {
        match size {
            1 => Ok(Self::U8),
            2 => Ok(Self::U16),
            4 => Ok(Self::U32),
            8 => Ok(Self::U64),
            _ => Err(Error::unsupported_address_size(size)),
        }
    }

    fn read<O: ByteOrder>(self, values: &[u8]) -> u64 {
        match self {
            Self::U8 => u8::read_bytes::<O>(values) as u64,
            Self::U16 => u16::read_bytes::<O>(values) as u64,
            Self::U32 => u32::read_bytes::<O>(values) as u64,
            Self::U64 => u64::read_bytes::<O>(values),
        }
    }

    fn write<O: ByteOrder>(self, value: Address, values: &mut [u8]) {
        match self {
            Self::U8 => u8::from(value).write_bytes::<O>(values),
            Self::U16 => u16::from(value).write_bytes::<O>(values),
            Self::U32 => u32::from(value).write_bytes::<O>(values),
            Self::U64 => u64::from(value).write_bytes::<O>(values),
        }
    }
}

#[derive(Clone)]
pub struct PCodeState<O: ByteOrder> {
    memory: PagedState,
    registers: RegisterState,
    temporaries: UniqueState,
    language: &'static Language,
    marker: PhantomData<O>,
}

impl<O: ByteOrder> PCodeState<O> {
    pub fn new(
        memory: PagedState,
        language: &'static Language,
        convention: &'static Convention,
    ) -> Self {
        Self {
            memory,
            registers: RegisterState::new(
                language.register_space_size(),
                language.program_counter(),
                convention.stack_pointer(),
            ),
            temporaries: UniqueState::new(language.unique_space_size()),
            language,
            marker: PhantomData,
        }
    }

    pub fn address_size(&self) -> usize {
        self.language.address_size()
    }

    pub fn global_space_id(&self) -> AddressSpaceId {
        self.language.space_id(self.language.default_space())
    }

    pub fn register_space_id(&self) -> AddressSpaceId {
        self.language.space_id(self.language.register_space())
    }

    pub fn memory(&self) -> &PagedState {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut PagedState {
        &mut self.memory
    }

    pub fn registers(&self) -> &RegisterState {
        &self.registers
    }

    pub fn registers_mut(&mut self) -> &mut RegisterState {
        &mut self.registers
    }

    pub fn temporaries(&self) -> &UniqueState {
        &self.temporaries
    }

    pub fn temporaries_mut(&mut self) -> &mut UniqueState {
        &mut self.temporaries
    }

    pub fn program_counter_value(&self) -> Result<Address, Error> {
        self.get_register_address(self.registers.program_counter())
    }

    pub fn stack_pointer_value(&self) -> Result<Address, Error> {
        self.get_register_address(self.registers.stack_pointer())
    }

    pub fn get_pointer(&self, address: Address) -> Result<Address, Error> {
        let size = self.address_size();
        let pointer = PointerSize::new(size)?;
        let mut values = [0u8; 8];
        let values = &mut values[..size];
        self.memory
            .read_values(address, values)
            .map_err(Error::Memory)?;

        Ok(self.wrap_address(pointer.read::<O>(values)))
    }

    pub fn set_program_counter_value<A>(&mut self, value: A) -> Result<(), Error>
    where
        A: Into<Address>,
    {
        self.set_register_address(self.registers.program_counter(), value.into())
    }

    pub fn set_stack_pointer_value<A>(&mut self, value: A) -> Result<(), Error>
    where
        A: Into<Address>,
    {
        self.set_register_address(self.registers.stack_pointer(), value.into())
    }

    fn get_register_address(&self, register: Varnode) -> Result<Address, Error> {
        let pointer = PointerSize::new(register.size())?;
        let values = self
            .registers
            .view_values(register.offset(), register.size())
            .map_err(Error::Register)?;

        Ok(self.wrap_address(pointer.read::<O>(values)))
    }

    fn set_register_address(&mut self, register: Varnode, value: Address) -> Result<(), Error> {
        let pointer = PointerSize::new(register.size())?;
        let values = self
            .registers
            .view_values_mut(register.offset(), register.size())
            .map_err(Error::Register)?;

        pointer.write::<O>(value, values);
        Ok(())
    }

    fn wrap_address(&self, offset: u64) -> Address {
        Address::from(self.language.wrap_offset_in_default_space(offset))
    }
}

impl<O: ByteOrder> State for PCodeState<O> {
    type Error = Error;

    fn fork(&self) -> Self {
        self.clone()
    }

    fn restore(&mut self, other: &Self) {
        self.registers.restore(&other.registers);
        self.temporaries.restore(&other.temporaries);
        self.memory.restore(&other.memory);
    }
}
