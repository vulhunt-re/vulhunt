use std::borrow::Cow;
use std::fmt;

use fugue::bv::BitVec;

use crate::ir::traits::BitSize;
use crate::ir::{Expr, Term, Var};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitVecInterval {
    Top(u32),
    Interval(BitVec, BitVec),
    Bottom(u32),
}

impl BitSize for BitVecInterval {
    fn nbits(&self) -> u32 {
        match self {
            Self::Top(bits) | Self::Bottom(bits) => *bits,
            Self::Interval(lb, _) => lb.nbits(),
        }
    }
}

impl fmt::Display for BitVecInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Top(bits) => write!(f, "⊤.{bits}"),
            Self::Bottom(bits) => write!(f, "⊥.{bits}"),
            Self::Interval(lb, ub) => write!(f, "[{lb}, {ub}]"),
        }
    }
}

impl BitVecInterval {
    pub fn new(bits: u32) -> BitVecInterval {
        if bits == 0 {
            panic!("cannot have Interval of zero bits")
        }
        BitVecInterval::Top(bits)
    }

    pub fn is_top(&self) -> bool {
        matches!(self, Self::Top(_))
    }

    pub fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom(_))
    }

    pub fn is_signed(&self) -> bool {
        matches!(self, Self::Interval(lb, _) if lb.is_signed())
    }

    pub fn is_unsigned(&self) -> bool {
        matches!(self, Self::Interval(lb, _) if lb.is_unsigned())
    }

    pub fn with_lower_bound(&self, bound: BitVec) -> Self {
        let bits = self.nbits();

        debug_assert_eq!(bits, bound.nbits());

        let signed = bound.is_signed();

        let iv = if signed {
            self.signed()
        } else {
            self.unsigned()
        };

        match iv {
            Self::Bottom(_) => Self::Bottom(bits),
            Self::Interval(lb, ub) => {
                if ub >= bound {
                    Self::Interval(lb.max(bound.clone()), ub.max(bound))
                } else {
                    Self::Bottom(bits)
                }
            }
            Self::Top(_) => {
                let max_value = bound.max_value();
                Self::Interval(
                    bound,
                    if signed {
                        max_value.signed()
                    } else {
                        max_value.unsigned()
                    },
                )
            }
        }
    }

    pub fn with_upper_bound(&self, bound: BitVec) -> Self {
        let bits = self.nbits();

        debug_assert_eq!(bits, bound.nbits());

        let signed = bound.is_signed();

        let iv = if signed {
            self.signed()
        } else {
            self.unsigned()
        };

        match iv {
            Self::Bottom(_) => Self::Bottom(bits),
            Self::Interval(lb, ub) => {
                if lb <= bound {
                    Self::Interval(lb.min(bound.clone()), ub.min(bound))
                } else {
                    Self::Bottom(bits)
                }
            }
            Self::Top(_) => {
                let min_value = bound.min_value();
                Self::Interval(
                    if signed {
                        min_value.signed()
                    } else {
                        min_value.unsigned()
                    },
                    bound,
                )
            }
        }
    }

    pub fn unsigned(&self) -> Self {
        if self.is_signed() {
            if let Self::Interval(lb, ub) = self {
                let bits = self.nbits();

                let zero = BitVec::zero(bits as usize);
                let nlb = lb.unsigned_cast(bits as usize).max(zero.clone());
                let nub = ub.unsigned_cast(bits as usize).max(zero);

                if nlb <= nub {
                    Self::Interval(nlb, nub)
                } else {
                    Self::Bottom(bits)
                }
            } else {
                unreachable!()
            }
        } else {
            self.clone()
        }
    }

    pub fn signed(&self) -> Self {
        if self.is_unsigned() {
            if let Self::Interval(lb, ub) = self {
                let bits = self.nbits();

                let max_signed = BitVec::max_value_with(bits as usize, true).unsigned();

                let nlb = lb.min(&max_signed).signed_cast(bits as usize);
                let nub = ub.min(&max_signed).signed_cast(bits as usize);

                if nlb <= nub {
                    Self::Interval(nlb, nub)
                } else {
                    Self::Bottom(bits)
                }
            } else {
                unreachable!()
            }
        } else {
            self.clone()
        }
    }

    pub fn union(&self, other: &Self) -> Self {
        let bits = self.nbits();

        debug_assert_eq!(bits, other.nbits());

        let lsign = self.is_signed();
        let rsign = other.is_signed();

        match (self, other) {
            (Self::Bottom(_), _) | (_, Self::Bottom(_)) => Self::Bottom(bits),
            (Self::Top(_), _) | (_, Self::Top(_)) => Self::Top(bits),
            (Self::Interval(lb1, ub1), Self::Interval(lb2, ub2)) if lsign == rsign => {
                let nlb = lb1.min(lb2);
                let nub = ub1.max(ub2);

                if nlb <= nub {
                    Self::Interval(nlb.clone(), nub.clone())
                } else {
                    Self::Bottom(bits)
                }
            }
            _ => self.union(&if lsign {
                other.signed()
            } else {
                other.unsigned()
            }),
        }
    }

    pub fn intersection(&self, other: &Self) -> Self {
        let bits = self.nbits();

        debug_assert_eq!(bits, other.nbits());

        let lsign = self.is_signed();
        let rsign = other.is_signed();

        match (self, other) {
            (Self::Bottom(_), _) | (_, Self::Bottom(_)) => Self::Bottom(bits),
            (Self::Top(_), v) | (v, Self::Top(_)) => v.clone(),
            (Self::Interval(lb1, ub1), Self::Interval(lb2, ub2)) if lsign == rsign => {
                let nlb = lb1.max(lb2);
                let nub = ub1.min(ub2);

                if nlb <= nub {
                    Self::Interval(nlb.clone(), nub.clone())
                } else {
                    Self::Bottom(bits)
                }
            }
            _ => self.union(&if lsign {
                other.signed()
            } else {
                other.unsigned()
            }),
        }
    }

    pub fn invert(&self) -> Self {
        let bits = self.nbits();
        let sign = self.is_signed();

        match self {
            Self::Bottom(_) => Self::Top(bits),
            Self::Top(_) => Self::Bottom(bits),
            Self::Interval(lb1, ub1) => {
                if *lb1 == lb1.min_value() {
                    let nlb = ub1 + &BitVec::one(bits as usize);
                    let nub = ub1.max_value();

                    let (nlb, nub) = if sign {
                        (nlb.signed(), nub.signed())
                    } else {
                        (nlb.unsigned(), nub.unsigned())
                    };

                    if nlb <= nub {
                        Self::Interval(nlb, nub)
                    } else {
                        Self::Bottom(bits)
                    }
                } else if *ub1 == ub1.max_value() {
                    let nlb = lb1.min_value();
                    let nub = lb1 - &BitVec::one(bits as usize);

                    let (nlb, nub) = if sign {
                        (nlb.signed(), nub.signed())
                    } else {
                        (nlb.unsigned(), nub.unsigned())
                    };

                    if nlb <= nub {
                        Self::Interval(nlb, nub)
                    } else {
                        Self::Bottom(bits)
                    }
                } else {
                    Self::Bottom(bits)
                }
            }
        }
    }

    pub fn iter(&self) -> BitVecIntervalIter {
        BitVecIntervalIter(self.clone())
    }

    pub fn from_flags(cond: &Term<Expr>) -> Option<(Var, Self)> {
        Self::from_flags_with(cond, |expr| expr.canonical())
    }

    pub fn from_flags_with<F>(cond: &Term<Expr>, mut simplifier: F) -> Option<(Var, Self)>
    where
        F: FnMut(Cow<Term<Expr>>) -> Term<Expr>,
    {
        let cond = simplifier(Cow::Borrowed(cond));

        cond.cond_eq()
            .map(|(var, val)| (*var, Self::from(val.clone())))
            .or_else(|| {
                cond.cond_neq()
                    .map(|(var, val)| (*var, Self::from(val.clone()).invert()))
            })
            .or_else(|| {
                cond.cond_slt().map(|(var, val)| {
                    (
                        *var,
                        Self::new(var.nbits())
                            .with_upper_bound((val - &BitVec::one(var.nbits() as usize)).signed()),
                    )
                })
            })
            .or_else(|| {
                cond.cond_sle().map(|(var, val)| {
                    (
                        *var,
                        Self::new(var.nbits()).with_upper_bound(val.clone().signed()),
                    )
                })
            })
            .or_else(|| {
                cond.cond_sgt().map(|(var, val)| {
                    (
                        *var,
                        Self::new(var.nbits())
                            .with_lower_bound((val + &BitVec::one(var.nbits() as usize)).signed()),
                    )
                })
            })
            .or_else(|| {
                cond.cond_sge().map(|(var, val)| {
                    (
                        *var,
                        Self::new(var.nbits()).with_lower_bound(val.clone().signed()),
                    )
                })
            })
            .or_else(|| {
                cond.cond_lt().map(|(var, val)| {
                    (
                        *var,
                        Self::new(var.nbits())
                            .with_upper_bound(val - &BitVec::one(var.nbits() as usize)),
                    )
                })
            })
            .or_else(|| {
                cond.cond_le().map(|(var, val)| {
                    (
                        *var,
                        Self::new(var.nbits()).with_upper_bound(val.clone().unsigned()),
                    )
                })
            })
            .or_else(|| {
                cond.cond_gt().map(|(var, val)| {
                    (
                        *var,
                        Self::new(var.nbits())
                            .with_lower_bound(val + &BitVec::one(var.nbits() as usize)),
                    )
                })
            })
            .or_else(|| {
                cond.cond_ge().map(|(var, val)| {
                    (
                        *var,
                        Self::new(var.nbits()).with_lower_bound(val.clone().unsigned()),
                    )
                })
            })
    }
}

impl From<BitVec> for BitVecInterval {
    fn from(bv: BitVec) -> Self {
        Self::Interval(bv.clone(), bv)
    }
}

pub struct BitVecIntervalIter(BitVecInterval);

impl Iterator for BitVecIntervalIter {
    type Item = BitVec;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            BitVecInterval::Bottom(_) => None,
            BitVecInterval::Top(bits) => {
                let bits = *bits as usize;
                self.0 = BitVecInterval::Interval(
                    BitVec::one(bits),
                    BitVec::max_value_with(bits, false),
                );
                Some(BitVec::zero(bits))
            }
            BitVecInterval::Interval(lb, ub) => {
                let val = Some(lb.clone());
                if lb >= ub {
                    self.0 = BitVecInterval::Bottom(lb.nbits());
                } else {
                    *lb = &*lb + &BitVec::one(lb.bits());
                }
                val
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.0 {
            BitVecInterval::Bottom(_) => (0, Some(0)),
            BitVecInterval::Top(bits) => (1, 1usize.checked_shl(*bits).map(|v| v.wrapping_sub(1))),
            BitVecInterval::Interval(lb, ub) => (1, (ub - lb + BitVec::one(lb.bits())).to_usize()),
        }
    }
}
