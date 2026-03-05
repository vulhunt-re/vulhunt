use std::cmp::Ordering;
use std::ops::Deref;
use std::str::FromStr;

use bias_core::ir::{BitSize, BitVec as BitVecT, ToAddress};

use mlua::prelude::*;
use mlua::Variadic;

use crate::lua::api::AddressValue;

#[derive(Clone, FromLua)]
#[repr(transparent)]
pub struct BitVec(BitVecT);

impl From<BitVecT> for BitVec {
    fn from(bv: BitVecT) -> Self {
        Self(bv)
    }
}

impl Deref for BitVec {
    type Target = BitVecT;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl BitVec {
    pub fn register(lua: &Lua) -> LuaResult<()> {
        lua.globals().set("BitVec", lua.create_proxy::<Self>()?)?;
        Ok(())
    }

    pub(crate) fn from_u64(value: u64, bits: u32) -> Self {
        Self(BitVecT::from_u64(value, bits as _))
    }

    fn lift_cmp<F>(&self, rhs: &Self, f: F) -> bool
    where
        F: FnOnce(&BitVecT, &BitVecT) -> bool,
    {
        if self.0.is_signed() || rhs.0.is_signed() {
            self.lift_signed2_cmp(rhs, f)
        } else {
            self.lift_unsigned2_cmp(rhs, f)
        }
    }

    fn lift_signed2_cmp<F>(&self, rhs: &Self, f: F) -> bool
    where
        F: FnOnce(&BitVecT, &BitVecT) -> bool,
    {
        let lbits = self.0.bits();
        let rbits = rhs.0.bits();
        match lbits.cmp(&rbits) {
            Ordering::Less => f(
                &self.0.clone().signed().cast(rbits),
                &rhs.0.clone().signed(),
            ),
            Ordering::Greater => f(
                &self.0.clone().signed(),
                &rhs.0.clone().signed().cast(lbits),
            ),
            Ordering::Equal => f(&self.0.clone().signed(), &rhs.0.clone().signed()),
        }
    }

    fn lift_signed2<F>(&self, rhs: &Self, f: F) -> Self
    where
        F: FnOnce(&BitVecT, &BitVecT) -> BitVecT,
    {
        let lbits = self.0.bits();
        let rbits = rhs.0.bits();
        Self(match lbits.cmp(&rbits) {
            Ordering::Less => f(&self.0.signed_cast(rbits), &rhs.0.clone().signed()),
            Ordering::Greater => f(&self.0.clone().signed(), &rhs.0.signed_cast(lbits)),
            Ordering::Equal => f(&self.0.clone().signed(), &rhs.clone().0.signed()),
        })
    }

    fn lift_unsigned2_cmp<F>(&self, rhs: &Self, f: F) -> bool
    where
        F: FnOnce(&BitVecT, &BitVecT) -> bool,
    {
        let lbits = self.0.bits();
        let rbits = rhs.0.bits();
        match lbits.cmp(&rbits) {
            Ordering::Less => f(&(self.0.clone()).cast(rbits), &rhs.0),
            Ordering::Greater => f(&self.0, &(rhs.0.clone()).cast(lbits)),
            Ordering::Equal => f(&self.0, &rhs.0),
        }
    }

    fn lift_unsigned2<F>(&self, rhs: &Self, f: F) -> Self
    where
        F: FnOnce(&BitVecT, &BitVecT) -> BitVecT,
    {
        let lbits = self.0.bits();
        let rbits = rhs.0.bits();
        Self(match lbits.cmp(&rbits) {
            Ordering::Less => f(&self.0.clone().cast(rbits), &rhs.0),
            Ordering::Greater => f(&self.0, &rhs.0.clone().cast(lbits)),
            Ordering::Equal => f(&self.0, &rhs.0),
        })
    }
}

fn ensure_valid_bits(bits: u32) -> LuaResult<()> {
    if bits == 0 || bits > 2048 {
        return Err(LuaError::RuntimeError(
            "bit size must be between 1 and 2048".into(),
        ));
    }
    Ok(())
}

fn ensure_min_size(bv: &BitVecT, min: usize) -> LuaResult<()> {
    if bv.bits() >= min {
        Ok(())
    } else {
        Err(LuaError::RuntimeError(format!(
            "given BitVec is smaller than required minimum size ({min:#x})"
        )))
    }
}

impl LuaUserData for BitVec {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("add", |_, this, other: BitVec| {
            Ok(this.lift_unsigned2(&other, |l, r| l + r))
        });
        methods.add_method("signed_add", |_, this, other: BitVec| {
            Ok(this.lift_signed2(&other, |l, r| l + r))
        });

        methods.add_method("sub", |_, this, other: BitVec| {
            Ok(this.lift_unsigned2(&other, |l, r| l - r))
        });
        methods.add_method("signed_sub", |_, this, other: BitVec| {
            Ok(this.lift_signed2(&other, |l, r| l - r))
        });

        methods.add_method("mul", |_, this, other: BitVec| {
            Ok(this.lift_unsigned2(&other, |l, r| l * r))
        });
        methods.add_method("signed_mul", |_, this, other: BitVec| {
            Ok(this.lift_signed2(&other, |l, r| l * r))
        });

        methods.add_method("div", |_, this, other: BitVec| {
            if other.0.is_zero() {
                return Err(LuaError::RuntimeError("division by zero".into()));
            }
            Ok(this.lift_unsigned2(&other, |l, r| l / r))
        });
        methods.add_method("signed_div", |_, this, other: BitVec| {
            if other.0.is_zero() {
                return Err(LuaError::RuntimeError("division by zero".into()));
            }
            Ok(this.lift_signed2(&other, |l, r| l / r))
        });

        methods.add_method("mod", |_, this, other: BitVec| {
            if other.0.is_zero() {
                return Err(LuaError::RuntimeError("modulo by zero".into()));
            }
            Ok(this.lift_unsigned2(&other, |l, r| l % r))
        });
        methods.add_method("signed_mod", |_, this, other: BitVec| {
            if other.0.is_zero() {
                return Err(LuaError::RuntimeError("modulo by zero".into()));
            }
            Ok(this.lift_signed2(&other, |l, r| l % r))
        });

        methods.add_method("carry", |_, this, other: BitVec| {
            Ok(this.lift_unsigned2(&other, |l, r| {
                if l.carry(r) {
                    BitVecT::one(8)
                } else {
                    BitVecT::zero(8)
                }
            }))
        });
        methods.add_method("signed_carry", |_, this, other: BitVec| {
            Ok(this.lift_signed2(&other, |l, r| {
                if l.signed_carry(r) {
                    BitVecT::one(8)
                } else {
                    BitVecT::zero(8)
                }
            }))
        });
        methods.add_method("signed_borrow", |_, this, other: BitVec| {
            Ok(this.lift_signed2(&other, |l, r| {
                if l.signed_borrow(r) {
                    BitVecT::one(8)
                } else {
                    BitVecT::zero(8)
                }
            }))
        });

        methods.add_method("signed", |_, this, ()| Ok(Self(this.0.clone().signed())));
        methods.add_method("unsigned", |_, this, ()| {
            Ok(Self(this.0.clone().unsigned()))
        });
        methods.add_method("cast", |_, this, bits: u32| {
            ensure_valid_bits(bits)?;
            Ok(Self(this.0.clone().cast(bits as _)))
        });
        methods.add_method("unsigned_cast", |_, this, bits: u32| {
            ensure_valid_bits(bits)?;
            Ok(Self(this.0.unsigned_cast(bits as _)))
        });
        methods.add_method("signed_cast", |_, this, bits: u32| {
            ensure_valid_bits(bits)?;
            Ok(Self(this.0.signed_cast(bits as _)))
        });

        methods.add_method("is_one", |_, this, ()| Ok(this.0.is_one()));
        methods.add_method("is_zero", |_, this, ()| Ok(this.0.is_zero()));

        methods.add_method("msb", |_, this, ()| Ok(this.0.msb()));
        methods.add_method("lsb", |_, this, ()| Ok(this.0.lsb()));

        methods.add_method("is_signed", |_, this, ()| Ok(this.0.is_signed()));
        methods.add_method("is_unsigned", |_, this, ()| Ok(this.0.is_unsigned()));

        methods.add_method("bits", |_, this, ()| Ok(this.0.bits()));

        methods.add_method("abs", |_, this, ()| Ok(Self(this.0.abs())));
        methods.add_method("neg", |_, this, ()| Ok(Self(-(&this.0))));

        methods.add_method("bnot", |_, this, ()| Ok(Self(!&this.0)));
        methods.add_method("band", |_, this, other: BitVec| {
            Ok(this.lift_unsigned2(&other, |l, r| l & r))
        });
        methods.add_method("bor", |_, this, other: BitVec| {
            Ok(this.lift_unsigned2(&other, |l, r| l | r))
        });
        methods.add_method("bxor", |_, this, other: BitVec| {
            Ok(this.lift_unsigned2(&other, |l, r| l ^ r))
        });

        methods.add_method("shl", |_, this, shift: BitVec| {
            Ok(this.lift_unsigned2(&shift, |l, r| l << r))
        });
        methods.add_method("shr", |_, this, shift: BitVec| {
            Ok(this.lift_unsigned2(&shift, |l, r| l >> r))
        });
        methods.add_method("signed_shr", |_, this, shift: BitVec| {
            Ok(this.lift_signed2(&shift, |l, r| l.clone().signed_shr(r)))
        });

        methods.add_method("count_ones", |_, this, ()| Ok(this.0.count_ones()));
        methods.add_method("count_zeros", |_, this, ()| Ok(this.0.count_zeros()));

        methods.add_method("leading_ones", |_, this, ()| Ok(this.0.leading_ones()));
        methods.add_method("leading_zeros", |_, this, ()| Ok(this.0.leading_zeros()));

        methods.add_method("succ", |_, this, ()| Ok(Self(this.0.succ())));
        methods.add_method("incr_by", |_, this, other: u64| {
            Ok(Self(this.0.incr(other)))
        });
        methods.add_method("pred", |_, this, ()| Ok(Self(this.0.pred())));
        methods.add_method("decr_by", |_, this, other: u64| {
            Ok(Self(this.0.decr(other)))
        });

        methods.add_method("extract", |_, this, (loff, moff): (u32, u32)| {
            if moff <= loff {
                return Err(LuaError::RuntimeError(
                    "invalid extract range: moff must be greater than loff".into(),
                ));
            }

            if moff as usize > this.0.bits() {
                return Err(LuaError::RuntimeError(
                    "invalid extract range: moff exceeds bit-vector size".into(),
                ));
            }

            let nval = if loff > 0 {
                (&this.0 >> loff).unsigned_cast((moff - loff) as usize)
            } else {
                this.0.clone().unsigned_cast((moff - loff) as usize)
            };

            Ok(Self(nval))
        });

        methods.add_method("concat", |_, this, other: BitVec| {
            let bits = this.0.bits() + other.0.bits();
            let nval = this.0.unsigned_cast(bits) << other.0.nbits() | other.0.unsigned_cast(bits);
            Ok(Self(nval))
        });

        methods.add_method("is_exactly_equal", |_, this, other: BitVec| {
            if this.0.bits() != other.0.bits() {
                return Ok(false);
            }
            Ok(this.0 == other.0)
        });

        methods.add_method("to_address", |lua, this, ()| {
            let addr = this.0.to_address().ok_or_else(|| {
                LuaError::RuntimeError("bit-vector too large to convert to address".into())
            })?;
            AddressValue::new_ser(lua, addr)
        });
        methods.add_method("to_u64", |_, this, ()| {
            this.0.to_u64().ok_or_else(|| {
                LuaError::RuntimeError("bit-vector too large to convert to u64".into())
            })
        });
        methods.add_method("to_i64", |_, this, ()| {
            let bv = if this.0.is_signed() && this.0.bits() < 64 {
                this.0.signed_cast(64)
            } else {
                this.0.clone()
            };
            bv.to_i64().ok_or_else(|| {
                LuaError::RuntimeError("bit-vector too large to convert to i64".into())
            })
        });
        methods.add_method("to_u32", |_, this, ()| {
            this.0.to_u32().ok_or_else(|| {
                LuaError::RuntimeError("bit-vector too large to convert to u32".into())
            })
        });
        methods.add_method("to_i32", |_, this, ()| {
            let bv = if this.0.is_signed() && this.0.bits() < 32 {
                this.0.signed_cast(32)
            } else {
                this.0.clone()
            };
            bv.to_i32().ok_or_else(|| {
                LuaError::RuntimeError("bit-vector too large to convert to i32".into())
            })
        });

        methods.add_method("to_be_bytes", |_, this, ()| {
            let mut bytes = vec![0u8; (this.0.bits() + 7) / 8];
            this.0.to_be_bytes(&mut bytes);
            Ok(bytes)
        });
        methods.add_method("to_le_bytes", |_, this, ()| {
            let mut bytes = vec![0u8; (this.0.bits() + 7) / 8];
            this.0.to_le_bytes(&mut bytes);
            Ok(bytes)
        });
        methods.add_method("to_bytes", |_, this, ()| {
            let mut bytes = vec![0u8; (this.0.bits() + 7) / 8];
            this.0.to_ne_bytes(&mut bytes);
            Ok(bytes)
        });

        methods.add_method("to_string", |_, this, ()| Ok(this.0.to_string()));
        methods.add_method("to_hex_string", |_, this, ()| Ok(format!("{:#x}", this.0)));
        methods.add_method("to_binary_string", |_, this, ()| {
            Ok(format!("{:#b}", this.0))
        });

        methods.add_function("from_be_bytes", |_, bytes: Vec<u8>| {
            if bytes.is_empty() {
                return Err(LuaError::RuntimeError(
                    "byte array must not be empty".into(),
                ));
            }
            Ok(Self(BitVecT::from_be_bytes(&bytes)))
        });
        methods.add_function("from_le_bytes", |_, bytes: Vec<u8>| {
            if bytes.is_empty() {
                return Err(LuaError::RuntimeError(
                    "byte array must not be empty".into(),
                ));
            }
            Ok(Self(BitVecT::from_le_bytes(&bytes)))
        });

        methods.add_function("from_integer", |_, (value, bits): (u64, u32)| {
            ensure_valid_bits(bits)?;
            Ok(Self(BitVecT::from_u64(value, bits as _)))
        });
        methods.add_function("from_signed_integer", |_, (value, bits): (i64, u32)| {
            ensure_valid_bits(bits)?;
            Ok(Self(BitVecT::from_i64(value, bits as _).signed()))
        });

        methods.add_function("from_address", |_, (addr, bits): (AddressValue, u32)| {
            ensure_valid_bits(bits)?;
            let addr = addr.value();
            Ok(Self(BitVecT::from_u64(addr, bits as _)))
        });
        methods.add_function("from_string", |_, s: String| {
            let bv = BitVecT::from_str(&s).map_err(|e| {
                LuaError::RuntimeError(format!("failed to parse BitVec from string: {e}"))
            })?;
            ensure_valid_bits(bv.bits() as u32)?;
            Ok(Self(bv))
        });

        methods.add_function("zero", |_, bits: u32| {
            ensure_valid_bits(bits)?;
            Ok(Self(BitVecT::zero(bits as _)))
        });
        methods.add_function("one", |_, bits: u32| {
            ensure_valid_bits(bits)?;
            Ok(Self(BitVecT::one(bits as _)))
        });

        methods.add_function("new", |_, args: (LuaValue, Variadic<u32>)| match args.0 {
            LuaValue::Integer(i) => {
                let bits = if let Some(&bits) = args.1.first() {
                    ensure_valid_bits(bits)?;
                    bits as usize
                } else {
                    return Err(LuaError::RuntimeError(
                        "bit size must be specified when constructing BitVec from an integer"
                            .into(),
                    ));
                };
                let mut bv = BitVecT::from_i64(i, bits);
                if i < 0 {
                    bv = bv.signed();
                }
                Ok(Self(bv))
            }
            LuaValue::String(s) => {
                let s = s.to_str()?;
                let bv = BitVecT::from_str(&s).map_err(|e| {
                    LuaError::RuntimeError(format!("failed to parse BitVec from string: {e}"))
                })?;
                ensure_valid_bits(bv.bits() as u32)?;
                Ok(Self(bv))
            }
            LuaValue::UserData(ud) => {
                if let Ok(av) = ud.borrow::<AddressValue>() {
                    let bits = if let Some(&bits) = args.1.first() {
                        ensure_valid_bits(bits)?;
                        bits as usize
                    } else {
                        return Err(LuaError::RuntimeError(
                            "bit size must be specified when constructing BitVec from an Address"
                                .into(),
                        ));
                    };

                    return Ok(Self(BitVecT::from_u64(av.value(), bits as _)));
                }

                if let Ok(bv) = ud.borrow::<BitVec>() {
                    let mut nbv = bv.0.clone();
                    if let Some(&bits) = args.1.first() {
                        ensure_valid_bits(bits)?;
                        nbv.cast_assign(bits as _);
                    };

                    return Ok(Self(nbv));
                }

                Err(LuaError::RuntimeError(
                    "invalid user data type for BitVec.new".into(),
                ))
            }
            LuaValue::Number(n) => {
                let bits = if let Some(&bits) = args.1.first() {
                    ensure_valid_bits(bits)?;
                    bits as usize
                } else {
                    return Err(LuaError::RuntimeError(
                        "bit size must be specified when constructing BitVec from a number".into(),
                    ));
                };
                let i = n as i64;
                let mut bv = BitVecT::from_i64(i, bits);
                if i < 0 {
                    bv = bv.signed();
                }
                Ok(Self(bv))
            }
            _ => Err(LuaError::RuntimeError(
                "invalid arguments to BitVec.new".into(),
            )),
        });

        methods.add_meta_method(LuaMetaMethod::Unm, |_, this, ()| Ok(Self(-(&this.0))));

        methods.add_meta_method(LuaMetaMethod::Add, |_, this, other: BitVec| {
            Ok(this.lift_unsigned2(&other, |l, r| l + r))
        });
        methods.add_meta_method(LuaMetaMethod::Sub, |_, this, other: BitVec| {
            Ok(this.lift_unsigned2(&other, |l, r| l - r))
        });
        methods.add_meta_method(LuaMetaMethod::Mul, |_, this, other: BitVec| {
            Ok(this.lift_unsigned2(&other, |l, r| l * r))
        });
        methods.add_meta_method(LuaMetaMethod::Div, |_, this, other: BitVec| {
            if other.0.is_zero() {
                return Err(LuaError::RuntimeError("division by zero".into()));
            }
            Ok(this.lift_unsigned2(&other, |l, r| l / r))
        });
        methods.add_meta_method(LuaMetaMethod::Mod, |_, this, other: BitVec| {
            if other.0.is_zero() {
                return Err(LuaError::RuntimeError("modulo by zero".into()));
            }
            Ok(this.lift_unsigned2(&other, |l, r| l % r))
        });

        methods.add_meta_method(LuaMetaMethod::Eq, |_, this, other: BitVec| {
            Ok(this.lift_cmp(&other, |l, r| l == r))
        });
        methods.add_meta_method(LuaMetaMethod::Lt, |_, this, other: BitVec| {
            Ok(this.lift_cmp(&other, |l, r| l < r))
        });
        methods.add_meta_method(LuaMetaMethod::Le, |_, this, other: BitVec| {
            Ok(this.lift_cmp(&other, |l, r| l <= r))
        });

        methods.add_meta_method(LuaMetaMethod::Concat, |_, this, other: BitVec| {
            let bits = this.0.bits() + other.0.bits();
            let nval = this.0.unsigned_cast(bits) << other.0.nbits() | other.0.unsigned_cast(bits);
            Ok(Self(nval))
        });

        methods.add_meta_method(LuaMetaMethod::Index, |_, this, index: u32| {
            ensure_min_size(&this.0, (index + 1) as usize)?;
            Ok(this.0.bit(index))
        });
        methods.add_meta_method(LuaMetaMethod::Len, |_, this, ()| Ok(this.0.bits()));

        methods.add_meta_method(LuaMetaMethod::ToString, |_, this, ()| {
            Ok(format!("{:#}", this.0))
        });
    }
}
