use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};

use fugue::core::ir::Address as StorageAddress;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
#[repr(transparent)]
pub struct Address(u64);

impl Address {
    pub const fn offset(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

macro_rules! impl_address_conversions {
    ($($t:ty),*) => {
        $(
            impl From<$t> for Address {
                fn from(value: $t) -> Self {
                    Self(value as u64)
                }
            }

            impl From<Address> for $t {
                fn from(value: Address) -> Self {
                    value.0 as $t
                }
            }

            impl From<&'_ Address> for $t {
                fn from(value: &Address) -> Self {
                    value.0 as $t
                }
            }

            impl PartialEq<$t> for Address {
                fn eq(&self, other: &$t) -> bool {
                    self.0 == *other as u64
                }
            }

            impl PartialEq<Address> for $t {
                fn eq(&self, other: &Address) -> bool {
                    *self as u64 == other.0
                }
            }
        )*
    };
}

impl_address_conversions!(u8, u16, u32, u64, usize);

impl From<Address> for StorageAddress {
    fn from(value: Address) -> Self {
        Self::in_default_space(value.0)
    }
}

macro_rules! impl_address_arithmetic {
    ($($t:ty => |$rhs:ident| $value:expr),* $(,)?) => {
        $(
            impl Add<$t> for Address {
                type Output = Self;

                fn add(self, $rhs: $t) -> Self {
                    Self(self.0.wrapping_add($value))
                }
            }

            impl Sub<$t> for Address {
                type Output = Self;

                fn sub(self, $rhs: $t) -> Self {
                    Self(self.0.wrapping_sub($value))
                }
            }

            impl AddAssign<$t> for Address {
                fn add_assign(&mut self, $rhs: $t) {
                    self.0 = self.0.wrapping_add($value);
                }
            }

            impl SubAssign<$t> for Address {
                fn sub_assign(&mut self, $rhs: $t) {
                    self.0 = self.0.wrapping_sub($value);
                }
            }
        )*
    };
}

impl_address_arithmetic! {
    Address => |rhs| rhs.0,
    &'_ Address => |rhs| rhs.0,
    usize => |rhs| rhs as u64,
    u64 => |rhs| rhs,
    u32 => |rhs| rhs as u64,
}
