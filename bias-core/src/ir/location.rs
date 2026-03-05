use std::borrow::Cow;
use std::fmt;
use std::ops::Add;

use fugue::ir::{Address, AddressValue, VarnodeData};

use crate::ir::traits::*;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct Location {
    pub address: Address,
    pub position: usize,
}

impl Default for Location {
    fn default() -> Self {
        Address::from(0u32).into()
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.address, self.position)
    }
}

pub struct LocationFormatter<'loc, 'trans> {
    loc: &'loc Location,
    fmt: Cow<'trans, TranslatorFormatter<'trans>>,
}

impl<'loc, 'trans> TranslatorDisplay<'loc, 'trans> for Location {
    type Target = LocationFormatter<'loc, 'trans>;

    fn display_full(&'loc self, fmt: Cow<'trans, TranslatorFormatter<'trans>>) -> Self::Target {
        LocationFormatter { loc: self, fmt }
    }
}

impl<'loc, 'trans> fmt::Display for LocationFormatter<'loc, 'trans> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}.{}{}",
            self.fmt.location_start, self.loc.address, self.loc.position, self.fmt.location_end
        )
    }
}

impl Add<usize> for Location {
    type Output = Self;

    fn add(self, rhs: usize) -> Self::Output {
        Self {
            position: self.position + rhs,
            ..self
        }
    }
}

impl Location {
    pub fn new<A>(address: A, position: usize) -> Location
    where
        A: Into<Address>,
    {
        Self {
            address: address.into(),
            position,
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub(super) fn absolute_from(
        base_address: &AddressValue,
        address: VarnodeData,
        position: usize,
    ) -> Self {
        if !address.space().is_constant() {
            return Self::new(address.offset(), 0); // position);
        }

        let offset = address.offset() as i64;
        let position = if offset.is_negative() {
            position
                .checked_sub(offset.abs() as usize)
                .expect("negative offset from position in valid range")
        } else {
            position
                .checked_add(offset as usize)
                .expect("positive offset from position in valid range")
        };

        Self {
            address: base_address.into(),
            position,
        }
    }
}

impl From<Address> for Location {
    fn from(address: Address) -> Self {
        Self {
            address,
            position: 0,
        }
    }
}
