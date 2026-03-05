use std::borrow::{Borrow, Cow};
use std::fmt;
use std::hash::Hash;
use std::ops::{Deref, Range};

use ahash::AHashMap;
use fugue::ir::disassembly::IRBuilderArena;
use fugue::ir::il::pcode::Operand;
use fugue::ir::space_manager::{FromSpace, SpaceManager};
use fugue::ir::{Address, AddressSpaceId, Translator, VarnodeData};
use iset::IntervalSet;

use super::Insn;
use crate::ir::traits::*;
use crate::kb::block::CodeBlock;
use crate::kb::function::Function;
use crate::kb::table::MPointTable;
use crate::lifter::Lifter;
use crate::Project;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct Var {
    pub(crate) space: AddressSpaceId,
    pub(crate) offset: u64,
    pub(crate) bits: u32,
    pub(crate) generation: u32,
}

impl Var {
    pub fn new<S: Into<AddressSpaceId>>(space: S, offset: u64, bits: u32, generation: u32) -> Self {
        Self {
            space: space.into(),
            offset,
            bits,
            generation,
        }
    }

    pub fn new0<S: Into<AddressSpaceId>>(space: S, offset: u64, bits: u32) -> Self {
        Self::new(space, offset, bits, 0)
    }

    #[inline]
    pub const fn from_parts(
        space: AddressSpaceId,
        offset: u64,
        bits: u32,
        generation: u32,
    ) -> Self {
        Self {
            space,
            offset,
            bits,
            generation,
        }
    }

    #[inline]
    pub const fn from_parts0(space: AddressSpaceId, offset: u64, bits: u32) -> Self {
        Self::from_parts(space, offset, bits, 0)
    }

    pub fn is_address(&self) -> bool {
        // !(self.is_register() || self.space.is_unique())
        self.space().is_default()
    }

    pub fn is_register(&self) -> bool {
        self.space.is_register()
    }

    pub fn is_temporary(&self) -> bool {
        self.space.is_unique()
    }

    pub fn address(&self) -> Option<Address> {
        if self.is_address() {
            Some(Address::from(self.offset))
        } else {
            None
        }
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn display<'t>(&'t self, project: &'t Project) -> VarFormatter<'t, 't> {
        self.display_with(Some(project.lifter().translator()))
    }
}

impl BitSize for Var {
    fn nbits(&self) -> u32 {
        self.bits
    }
}

impl Variable for Var {
    fn generation(&self) -> u32 {
        self.generation
    }

    fn generation_mut(&mut self) -> &mut u32 {
        &mut self.generation
    }

    fn with_generation(&self, generation: u32) -> Self {
        Self {
            space: self.space,
            generation,
            ..*self
        }
    }

    fn space(&self) -> AddressSpaceId {
        self.space
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct VarView {
    space: AddressSpaceId,
    intervals: IntervalSet<u64>,
}

impl<'ir> VisitVars<'ir> for VarView {
    fn visit_def(&mut self, var: &'ir Var) {
        if var.space() == self.space() {
            self.insert(var);
        }
    }

    fn visit_use(&mut self, var: &'ir Var) {
        if var.space() == self.space() {
            self.insert(var);
        }
    }
}

impl VarView {
    pub fn new(space: AddressSpaceId) -> Self {
        Self {
            space,
            intervals: Default::default(),
        }
    }

    pub fn space(&self) -> AddressSpaceId {
        self.space
    }

    pub fn intervals(&self) -> &IntervalSet<u64> {
        &self.intervals
    }

    pub fn insert(&mut self, var: &Var) {
        if var.space() != self.space() {
            return; // maybe panic
        }

        let range = var.offset..var.offset + (var.bits as u64 / 8);
        self.intervals.insert(range);
    }

    pub fn parent(&self, var: &Var) -> Option<Var> {
        if var.space() != self.space() {
            return None;
        }

        let range = var.offset..var.offset + (var.bits as u64 / 8);
        let overlaps = self.intervals.iter(range.clone());

        let ivlen = |iv: &Range<u64>| iv.end - iv.start;
        overlaps.max_by_key(ivlen).and_then(|iv| {
            if iv.start <= range.start && iv.end >= range.end {
                let bits = ivlen(&iv) as u32 * 8;
                Some(Var::new(self.space, iv.start, bits, 0))
            } else {
                None
            }
        })
    }

    pub fn variables<'a>(&'a self) -> impl Iterator<Item = Var> + 'a {
        self.intervals()
            .iter(..)
            .map(|iv| Var::new0(self.space(), iv.start, (iv.end - iv.start) as u32 * 8))
    }

    pub fn registers<T: Borrow<Translator>>(translator: T) -> VarView {
        let t = translator.borrow();
        let space_id = t.manager().register_space_id();

        Self {
            space: space_id,
            intervals: IntervalSet::from_iter(
                t.registers()
                    .iter()
                    .map(|((off, sz), _)| *off..(off + (*sz as u64))),
            ),
        }
    }

    pub fn clear(&mut self) {
        self.intervals.clear();
    }
}

#[derive(Debug, Clone)]
pub struct VarViews<'v>(AHashMap<AddressSpaceId, Cow<'v, VarView>>);

impl<'a> Default for VarViews<'a> {
    fn default() -> Self {
        Self(AHashMap::new())
    }
}

impl<'a, 'v> FromIterator<&'a Var> for VarViews<'v> {
    fn from_iter<T: IntoIterator<Item = &'a Var>>(iter: T) -> Self {
        let mut views = Self::default();
        for var in iter.into_iter() {
            views.insert(SimpleVar(*var))
        }
        views
    }
}

#[derive(Debug, Clone, Default)]
pub struct LocalVars<'r>(VarViews<'r>);

impl<'r> LocalVars<'r> {
    pub fn new(
        lifter: &'r Lifter,
        function: &Function,
        blocks: &MPointTable<Address, CodeBlock>,
    ) -> Self {
        let mut slf = Self(VarViews::from_view(&**lifter.register_map()));
        for blk in function.blocks_with(blocks) {
            blk.visit(&mut slf);
        }
        slf
    }

    pub fn insn(lifter: &'r Lifter, insn: &Insn) -> Self {
        let mut slf = Self(VarViews::from_view(&**&lifter.register_map()));
        for stmt in insn.operations() {
            slf.visit_stmt(stmt);
        }
        slf
    }

    pub fn enclosing<V>(&self, var: V) -> SimpleVar
    where
        V: Into<SimpleVar>,
    {
        self.0.enclosing(var)
    }
}

impl<'r, 'ir> Visit<'ir> for LocalVars<'r> {
    fn visit_var(&mut self, var: &'ir Var) {
        if !(var.space().is_register() || var.space().is_global()) {
            self.0.insert(*var);
        }
    }
}

impl<'v> VarViews<'v> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_view(vars: &'v VarView) -> Self {
        let mut m = AHashMap::new();
        m.insert(vars.space(), Cow::Borrowed(vars));
        Self(m)
    }

    pub fn insert<V: Into<SimpleVar>>(&mut self, var: V) {
        let (space, iv) = Self::interval(var);
        self.0
            .entry(space)
            .or_insert_with(|| Cow::Owned(VarView::new(space)))
            .to_mut()
            .intervals
            .insert(iv);
    }

    pub fn reset(&mut self) {
        self.0.retain(|s, _| s.is_register())
    }

    pub fn enclosing<V: Into<SimpleVar>>(&self, var: V) -> SimpleVar {
        let var = var.into();
        if let Some(ivs) = self.0.get(&var.space()) {
            ivs.parent(&var.0).map(SimpleVar).unwrap_or(var)
        } else {
            var
        }
    }

    /*
    pub fn overlaps<V: Into<SimpleVar>>(&self, var: V) -> Vec<SimpleVar> {
        let var = var.into();
        let (space, iv) = Self::interval(var);
        if let Some(ref ivs) = self.0.get(&space) {
            ivs.intervals
                .find_all(iv)
                .into_iter()
                .map(|e| {
                    let iv = e.interval();
                    SimpleVar(Var::new(
                        space,
                        *iv.start(),
                        8 * (1 + *iv.end() - *iv.start()) as u32,
                        var.generation(),
                    ))
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    }

    pub fn enclosing<V: Into<SimpleVar>>(&self, var: V) -> SimpleVar {
        let var = var.into();
        let (space, iv) = Self::interval(var);
        if let Some(ivs) = self.0.get(&space) {
            let iv = ivs
                .intervals()
                .find_all(&iv)
                .into_iter()
                .fold(&iv, |iv, ent| {
                    let eiv = ent.interval();
                    if (eiv.start() < iv.start() && eiv.end() >= iv.end())
                        || (eiv.start() <= iv.start() && eiv.end() > iv.end())
                    {
                        eiv
                    } else {
                        iv
                    }
                });
            SimpleVar(Var::new(
                space,
                *iv.start(),
                8 * (1 + *iv.end() - *iv.start()) as u32,
                var.generation(),
            ))
        } else {
            var
        }
    }
    */

    fn interval<V: Into<SimpleVar>>(var: V) -> (AddressSpaceId, Range<u64>) {
        let var = var.into();
        let iv = var.offset()..(var.offset() + (var.nbits() as u64) / 8);
        (var.space(), iv)
    }

    /*
    pub fn contains<V: Into<SimpleVar>>(&self, var: V) -> bool {
        let (space, iv) = Self::interval(var);
        self.0
            .get(&space)
            .map(|ivs| ivs.intervals().overlaps(iv))
            .unwrap_or(false)
    }

    // similar to contains, except only true if overlaps and not equal
    pub fn contains_partial<V: Into<SimpleVar>>(&self, var: V) -> bool {
        let (space, iv) = Self::interval(var);
        self.0
            .get(&space)
            .map(|ivs| ivs.intervals().overlaps(&iv) && ivs.intervals().find_exact(&iv).is_none())
            .unwrap_or(false)
    }
    */
}

impl fmt::Display for Var {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "space[{}][{:#x}].{}:{}",
            self.space().index(),
            self.offset(),
            self.generation(),
            self.nbits()
        )
    }
}

impl<'var, 'trans> fmt::Display for VarFormatter<'var, 'trans> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.var.space().is_unmapped() {
            return self.var.fmt(f);
        }

        if let Some(trans) = self.fmt.translator {
            let space = unsafe { trans.manager().unchecked_space_by_id(self.var.space()) };
            if space.is_register() {
                if let Some(name) = trans
                    .registers()
                    .get(self.var.offset(), self.var.nbits() as usize / 8)
                {
                    write!(
                        f,
                        "{}{}{}.{}{}{}:{}{}{}",
                        self.fmt.variable_start,
                        name,
                        self.fmt.variable_end,
                        self.fmt.value_start,
                        self.var.generation(),
                        self.fmt.value_end,
                        self.fmt.value_start,
                        self.var.nbits(),
                        self.fmt.value_end,
                    )
                } else {
                    let off = self.var.offset();
                    let sig = (off as i64).signum() as i128;
                    write!(
                        f,
                        "{}{}{}[{}{}{}{}{:#x}{}].{}{}{}:{}{}{}",
                        self.fmt.variable_start,
                        space.name(),
                        self.fmt.variable_end,
                        self.fmt.keyword_start,
                        if sig == 0 {
                            ""
                        } else if sig > 0 {
                            "+"
                        } else {
                            "-"
                        },
                        self.fmt.keyword_end,
                        self.fmt.value_start,
                        self.var.offset() as i64 as i128 * sig,
                        self.fmt.value_end,
                        self.fmt.value_start,
                        self.var.generation(),
                        self.fmt.value_end,
                        self.fmt.value_start,
                        self.var.nbits(),
                        self.fmt.value_end,
                    )
                }
            } else if space.is_unique() {
                write!(
                    f,
                    "{}var{:#x}{}.{}{}{}:{}{}{}",
                    self.fmt.variable_start,
                    self.var.offset(),
                    self.fmt.variable_end,
                    self.fmt.value_start,
                    self.var.generation(),
                    self.fmt.value_end,
                    self.fmt.value_start,
                    self.var.nbits(),
                    self.fmt.value_end,
                )
            } else {
                let off = self.var.offset();
                let sig = (off as i64).signum() as i128;
                write!(
                    f,
                    "{}{}{}[{}{}{}{}{:#x}{}].{}{}{}:{}{}{}",
                    self.fmt.variable_start,
                    space.name(),
                    self.fmt.variable_end,
                    self.fmt.keyword_start,
                    if sig == 0 {
                        ""
                    } else if sig > 0 {
                        "+"
                    } else {
                        "-"
                    },
                    self.fmt.keyword_end,
                    self.fmt.value_start,
                    self.var.offset() as i64 as i128 * sig,
                    self.fmt.value_end,
                    self.fmt.value_start,
                    self.var.generation(),
                    self.fmt.value_end,
                    self.fmt.value_start,
                    self.var.nbits(),
                    self.fmt.value_end,
                )
            }
        } else {
            if self.var.space().is_unique() {
                write!(
                    f,
                    "{}var{:#x}{}.{}{}{}:{}{}{}",
                    self.fmt.variable_start,
                    self.var.offset(),
                    self.fmt.variable_end,
                    self.fmt.value_start,
                    self.var.generation(),
                    self.fmt.value_end,
                    self.fmt.value_start,
                    self.var.nbits(),
                    self.fmt.value_end,
                )
            } else {
                self.var.fmt(f)
            }
        }
    }
}

pub struct VarFormatter<'var, 'trans> {
    var: &'var Var,
    fmt: Cow<'trans, TranslatorFormatter<'trans>>,
}

impl<'var, 'trans> TranslatorDisplay<'var, 'trans> for Var {
    type Target = VarFormatter<'var, 'trans>;

    fn display_full(
        &'var self,
        fmt: Cow<'trans, TranslatorFormatter<'trans>>,
    ) -> VarFormatter<'var, 'trans> {
        VarFormatter { var: self, fmt }
    }
}

impl From<VarnodeData> for Var {
    fn from(vnd: VarnodeData) -> Self {
        Self {
            space: vnd.space(),
            offset: vnd.offset(),
            bits: vnd.size() as u32 * 8,
            generation: 0,
        }
    }
}

impl<'z> FromSpace<'z, Operand> for Var {
    fn from_space_with(t: Operand, _arena: &'z IRBuilderArena, manager: &SpaceManager) -> Self {
        Var::from_space(t, manager)
    }

    fn from_space(operand: Operand, manager: &SpaceManager) -> Self {
        match operand {
            Operand::Address { value, size } => Var {
                offset: value.offset(),
                space: manager.default_space_id(),
                bits: size as u32 * 8,
                generation: 0,
            },
            Operand::Register { offset, size, .. } => Var {
                offset,
                space: manager.register_space_id(),
                bits: size as u32 * 8,
                generation: 0,
            },
            Operand::Variable {
                offset,
                space,
                size,
            } => Var {
                offset,
                space,
                bits: size as u32 * 8,
                generation: 0,
            },
            _ => panic!("cannot create Var from Operand::Constant"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SimpleVar(pub Var);

impl SimpleVar {
    pub fn new<S: Into<AddressSpaceId>>(space: S, offset: u64, nbits: u32) -> Self {
        Self(Var::new0(space, offset, nbits))
    }

    pub fn display<'t>(&'t self, project: &'t Project) -> SimpleVarFormatter<'t, 't> {
        self.display_with(Some(project.lifter().translator()))
    }
}

impl From<&'_ Var> for SimpleVar {
    fn from(var: &Var) -> Self {
        Self(*var)
    }
}

impl From<Var> for SimpleVar {
    fn from(var: Var) -> Self {
        Self(var)
    }
}

impl PartialEq for SimpleVar {
    fn eq(&self, other: &Self) -> bool {
        self.0.space() == other.0.space()
            && self.0.offset() == other.0.offset()
            && self.0.nbits() == other.0.nbits()
    }
}
impl Eq for SimpleVar {}

impl PartialOrd for SimpleVar {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0
            .space()
            .partial_cmp(&other.0.space())
            .and_then(|ord| {
                ord.is_eq()
                    .then(|| {
                        self.0
                            .offset()
                            .partial_cmp(&other.0.offset())
                            .and_then(|ord| {
                                if ord.is_eq() {
                                    self.0.nbits().partial_cmp(&other.0.nbits())
                                } else {
                                    Some(ord)
                                }
                            })
                    })
                    .unwrap_or(Some(ord))
            })
    }
}

impl Ord for SimpleVar {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl Hash for SimpleVar {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.space().hash(state);
        self.0.offset().hash(state);
        self.0.nbits().hash(state);
    }
}

impl Deref for SimpleVar {
    type Target = Var;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for SimpleVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "space[{}][{:#x}]:{}",
            self.space().index(),
            self.offset(),
            self.nbits()
        )
    }
}

impl<'var, 'trans> fmt::Display for SimpleVarFormatter<'var, 'trans> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.var.space().is_unmapped() {
            return self.var.fmt(f);
        }

        if let Some(trans) = self.fmt.translator {
            let space = unsafe { trans.manager().unchecked_space_by_id(self.var.space()) };
            if space.is_register() {
                if let Some(name) = trans
                    .registers()
                    .get(self.var.offset(), self.var.nbits() as usize / 8)
                {
                    write!(
                        f,
                        "{}{}{}:{}{}{}",
                        self.fmt.variable_start,
                        name,
                        self.fmt.variable_end,
                        self.fmt.value_start,
                        self.var.nbits(),
                        self.fmt.value_end,
                    )
                } else {
                    let off = self.var.offset();
                    let sig = (off as i64).signum() as i128;
                    write!(
                        f,
                        "{}{}{}[{}{}{}{}{:#x}{}]:{}{}{}",
                        self.fmt.variable_start,
                        space.name(),
                        self.fmt.variable_end,
                        self.fmt.keyword_start,
                        if sig == 0 {
                            ""
                        } else if sig > 0 {
                            "+"
                        } else {
                            "-"
                        },
                        self.fmt.keyword_end,
                        self.fmt.value_start,
                        self.var.offset() as i64 as i128 * sig,
                        self.fmt.value_end,
                        self.fmt.value_start,
                        self.var.nbits(),
                        self.fmt.value_end,
                    )
                }
            } else if space.is_unique() {
                write!(
                    f,
                    "{}var{:#x}{}:{}{}{}",
                    self.fmt.variable_start,
                    self.var.offset(),
                    self.fmt.variable_end,
                    self.fmt.value_start,
                    self.var.nbits(),
                    self.fmt.value_end,
                )
            } else {
                let off = self.var.offset();
                let sig = (off as i64).signum() as i128;
                write!(
                    f,
                    "{}{}{}[{}{}{}{}{:#x}{}]:{}{}{}",
                    self.fmt.variable_start,
                    space.name(),
                    self.fmt.variable_end,
                    self.fmt.keyword_start,
                    if sig == 0 {
                        ""
                    } else if sig > 0 {
                        "+"
                    } else {
                        "-"
                    },
                    self.fmt.keyword_end,
                    self.fmt.value_start,
                    self.var.offset() as i64 as i128 * sig,
                    self.fmt.value_end,
                    self.fmt.value_start,
                    self.var.nbits(),
                    self.fmt.value_end,
                )
            }
        } else {
            if self.var.space().is_unique() {
                write!(
                    f,
                    "{}var{:#x}{}:{}{}{}",
                    self.fmt.variable_start,
                    self.var.offset(),
                    self.fmt.variable_end,
                    self.fmt.value_start,
                    self.var.nbits(),
                    self.fmt.value_end,
                )
            } else {
                self.var.fmt(f)
            }
        }
    }
}

pub struct SimpleVarFormatter<'var, 'trans> {
    var: &'var SimpleVar,
    fmt: Cow<'trans, TranslatorFormatter<'trans>>,
}

impl<'var, 'trans> TranslatorDisplay<'var, 'trans> for SimpleVar {
    type Target = SimpleVarFormatter<'var, 'trans>;

    fn display_full(
        &'var self,
        fmt: Cow<'trans, TranslatorFormatter<'trans>>,
    ) -> SimpleVarFormatter<'var, 'trans> {
        SimpleVarFormatter { var: self, fmt }
    }
}
