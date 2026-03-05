#![allow(non_camel_case_types)]

use downcast_rs::{impl_downcast, DowncastSync};
use dyn_clone::{clone_trait_object, DynClone};
use fugue::bv::BitVec;
use fugue::ir::{Address, AddressSpaceId};
use smallvec::{smallvec, SmallVec};
use ustr::Ustr;

use super::Term;
use crate::cio::TypeDB;
use crate::ir::stmt::POINTER_HINT;
use crate::ir::traits::BitSize;
use crate::ir::types::{EnumVariant, FunctionArg, StructField, UnionVariant};
use crate::ir::{
    BinOp, BinRel, BranchTarget, Expr, Insn, Location, Stmt, Type, TypeKind, UnOp, UnRel, Var,
};
use crate::kb::block::CodeBlock;
use crate::kb::phi::Phi;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum OpType {
    BLOCK,
    INSN,
    PHI,

    // Statements
    ASSIGN,
    STORE,
    BRANCH,
    CBRANCH,
    CALL,
    RETURN,
    SKIP,
    INTRINSIC,

    // Bit size/offset
    OFFSET,

    // Location
    LOCATION,

    // Expressions
    VAR,
    VAL,

    LOAD,
    CAST,
    IFELSE,
    EXTRACT,
    CONCAT,
    CHOICE,

    // UnRel
    NAN,

    // UnOp
    NOT,
    NEG,
    ABS,
    SQRT,
    CEILING,
    FLOOR,
    ROUND,
    POPCOUNT,

    // BinOp
    AND,
    OR,
    XOR,
    ADD,
    SUB,
    DIV,
    SDIV,
    MUL,
    REM,
    SREM,
    SHL,
    SAR,
    SHR,

    // BinRel
    EQ,
    NEQ,
    LT,
    LE,
    SLT,
    SLE,

    SBORROW,
    CARRY,
    SCARRY,

    // Type
    TYPE,
    STRUCT_FIELD,
    FUNC_ARG,
    ENUM_VARIANT,
    UNION_VARIANT,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SubType {
    VOID,
    BOOL,
    CHAR,
    UNSIGNED_CHAR,
    CHAR16,
    CHAR32,
    WCHAR,
    UNSIGNED_WCHAR,
    INT,
    UNSIGNED_INT,
    FLOAT,
    POINTER,
    SHIFTED_POINTER,
    STRUCT,
    FUNC,
    ENUM,
    UNION,
    ARRAY,
    INCOMPLETE_ARRAY,
    TYPEDEF,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ClassType {
    STMT,
    EXPR,
}

pub type OperandRefs<'a> = SmallVec<[&'a dyn AsTerm; 2]>;
pub type Operands = SmallVec<[Box<dyn AsTerm>; 2]>;

pub trait AsTerm: DynClone + DowncastSync {
    fn op_type(&self) -> OpType;

    fn op_sub_type(&self) -> Option<SubType> {
        None
    }

    fn op_class_type(&self) -> Option<ClassType> {
        None
    }

    fn operand_refs(&self) -> OperandRefs<'_> {
        Default::default()
    }

    fn operands(&self) -> Operands {
        self.operand_refs()
            .into_iter()
            .map(|opnd| dyn_clone::clone_box(opnd))
            .collect()
    }

    fn get_address(&self) -> Option<Address> {
        None
    }

    fn is_address(&self) -> bool {
        false
    }

    fn get_next_address(&self) -> Option<Address> {
        None
    }

    fn has_next_address(&self) -> bool {
        self.get_next_address().is_some()
    }

    fn get_variable(&self) -> Option<&Var> {
        None
    }

    fn is_variable(&self) -> bool {
        false
    }

    fn get_value(&self) -> Option<&BitVec> {
        None
    }

    fn is_value(&self) -> bool {
        false
    }

    fn get_offset(&self) -> Option<u32> {
        None
    }

    fn is_offset(&self) -> bool {
        false
    }

    fn get_shift_offset(&self) -> Option<i64> {
        None
    }

    fn is_shift_offset(&self) -> bool {
        false
    }

    fn get_type(&self) -> Option<&Type> {
        None
    }

    #[allow(unused_variables)]
    fn get_expanded_type(&self, db: &TypeDB) -> Option<Term<Type>> {
        None
    }

    fn get_type_name(&self) -> Option<Ustr> {
        None
    }

    fn get_lsb(&self) -> Option<u32> {
        None
    }

    fn get_msb(&self) -> Option<u32> {
        None
    }

    fn get_name(&self) -> Option<Ustr> {
        None
    }

    fn get_bits(&self) -> Option<u32> {
        None
    }

    fn get_nbytes(&self) -> Option<usize> {
        None
    }

    fn address_space(&self) -> Option<AddressSpaceId> {
        None
    }
}
impl_downcast!(sync AsTerm);
clone_trait_object!(AsTerm);

pub trait TermBox: AsTerm + Clone {
    fn to_boxed(&self) -> Box<dyn AsTerm> {
        dyn_clone::clone_box(self as _)
    }
}

impl<T> AsTerm for Term<T>
where
    T: AsTerm + Clone,
{
    fn op_type(&self) -> OpType {
        (**self).op_type()
    }

    fn op_sub_type(&self) -> Option<SubType> {
        (**self).op_sub_type()
    }

    fn op_class_type(&self) -> Option<ClassType> {
        (**self).op_class_type()
    }

    fn operand_refs(&self) -> OperandRefs<'_> {
        (**self).operand_refs()
    }

    fn operands(&self) -> Operands {
        (**self).operands()
    }

    fn get_address(&self) -> Option<Address> {
        (**self).get_address()
    }

    fn is_address(&self) -> bool {
        (**self).is_address()
    }

    fn get_next_address(&self) -> Option<Address> {
        (**self).get_next_address()
    }

    fn has_next_address(&self) -> bool {
        (**self).has_next_address()
    }

    fn get_variable(&self) -> Option<&Var> {
        (**self).get_variable()
    }

    fn is_variable(&self) -> bool {
        (**self).is_variable()
    }

    fn get_value(&self) -> Option<&BitVec> {
        (**self).get_value()
    }

    fn is_value(&self) -> bool {
        (**self).is_value()
    }

    fn get_offset(&self) -> Option<u32> {
        (**self).get_offset()
    }

    fn is_offset(&self) -> bool {
        (**self).is_offset()
    }

    fn get_shift_offset(&self) -> Option<i64> {
        (**self).get_shift_offset()
    }

    fn is_shift_offset(&self) -> bool {
        (**self).is_shift_offset()
    }

    fn get_type(&self) -> Option<&Type> {
        (**self).get_type()
    }

    fn get_expanded_type(&self, db: &TypeDB) -> Option<Term<Type>> {
        (**self).get_expanded_type(db)
    }

    fn get_type_name(&self) -> Option<Ustr> {
        None
    }

    fn get_lsb(&self) -> Option<u32> {
        (**self).get_lsb()
    }
    fn get_msb(&self) -> Option<u32> {
        (**self).get_msb()
    }

    fn get_name(&self) -> Option<Ustr> {
        (**self).get_name()
    }

    fn get_bits(&self) -> Option<u32> {
        (**self).get_bits()
    }

    fn get_nbytes(&self) -> Option<usize> {
        (**self).get_nbytes()
    }

    fn address_space(&self) -> Option<AddressSpaceId> {
        (**self).address_space()
    }
}

impl AsTerm for u32 {
    fn op_type(&self) -> OpType {
        OpType::OFFSET
    }

    fn get_offset(&self) -> Option<u32> {
        Some(*self)
    }

    fn is_offset(&self) -> bool {
        true
    }
}

impl AsTerm for i64 {
    fn op_type(&self) -> OpType {
        OpType::OFFSET
    }

    fn get_offset(&self) -> Option<u32> {
        Some(*self as i32 as u32)
    }

    fn get_shift_offset(&self) -> Option<i64> {
        Some(*self)
    }

    fn is_offset(&self) -> bool {
        true
    }

    fn is_shift_offset(&self) -> bool {
        true
    }
}

impl AsTerm for Var {
    fn op_type(&self) -> OpType {
        OpType::VAR
    }

    fn get_address(&self) -> Option<Address> {
        self.address()
    }

    fn is_variable(&self) -> bool {
        true
    }

    fn get_variable(&self) -> Option<&Var> {
        Some(self)
    }

    fn address_space(&self) -> Option<AddressSpaceId> {
        Some(self.space)
    }

    fn get_bits(&self) -> Option<u32> {
        Some(self.nbits())
    }
}

impl AsTerm for BitVec {
    fn op_type(&self) -> OpType {
        OpType::VAL
    }

    fn get_value(&self) -> Option<&BitVec> {
        Some(self)
    }

    fn is_value(&self) -> bool {
        true
    }

    fn get_address(&self) -> Option<Address> {
        self.to_u64().map(Address::from)
    }

    fn get_bits(&self) -> Option<u32> {
        Some(self.nbits())
    }
}

impl AsTerm for Option<BitVec> {
    fn op_type(&self) -> OpType {
        OpType::VAL
    }
}

impl AsTerm for Option<Term<Expr>> {
    fn op_type(&self) -> OpType {
        OpType::VAL
    }
}

impl AsTerm for Expr {
    fn op_type(&self) -> OpType {
        match self {
            Expr::Val(_, _) => OpType::VAL,
            Expr::Var(_) => OpType::VAR,
            Expr::Load(_, _, _) => OpType::LOAD,
            Expr::UnOp(op, _) => match op {
                UnOp::NOT => OpType::NOT,
                UnOp::NEG => OpType::NEG,
                UnOp::ABS => OpType::ABS,
                UnOp::SQRT => OpType::SQRT,
                UnOp::CEILING => OpType::CEILING,
                UnOp::FLOOR => OpType::FLOOR,
                UnOp::ROUND => OpType::ROUND,
                UnOp::POPCOUNT(_) => OpType::POPCOUNT,
            },
            Expr::BinOp(op, _, _) => match op {
                BinOp::AND => OpType::AND,
                BinOp::OR => OpType::OR,
                BinOp::XOR => OpType::XOR,
                BinOp::ADD => OpType::ADD,
                BinOp::SUB => OpType::SUB,
                BinOp::DIV => OpType::DIV,
                BinOp::SDIV => OpType::SDIV,
                BinOp::MUL => OpType::MUL,
                BinOp::REM => OpType::REM,
                BinOp::SREM => OpType::SREM,
                BinOp::SHL => OpType::SHL,
                BinOp::SAR => OpType::SAR,
                BinOp::SHR => OpType::SHR,
            },
            Expr::UnRel(op, _) => match op {
                UnRel::NAN => OpType::NAN,
            },
            Expr::BinRel(op, _, _) => match op {
                BinRel::EQ => OpType::EQ,
                BinRel::NEQ => OpType::NEQ,
                BinRel::LT => OpType::LT,
                BinRel::LE => OpType::LE,
                BinRel::SLT => OpType::SLT,
                BinRel::SLE => OpType::SLE,
                BinRel::SBORROW => OpType::SBORROW,
                BinRel::CARRY => OpType::CARRY,
                BinRel::SCARRY => OpType::SCARRY,
            },
            Expr::IfElse(_, _, _) => OpType::IFELSE,
            Expr::Choice(_, _, _, _) => OpType::CHOICE,
            Expr::Extract(_, _, _) => OpType::EXTRACT,
            Expr::ExtractHigh(_, _) => OpType::EXTRACT,
            Expr::ExtractLow(_, _) => OpType::EXTRACT,
            Expr::Concat(_, _) => OpType::CONCAT,
            Expr::Intrinsic(_, _, _) => OpType::INTRINSIC,
            Expr::Cast(_, _) => OpType::CAST,
        }
    }

    fn op_class_type(&self) -> Option<ClassType> {
        Some(ClassType::EXPR)
    }

    fn operand_refs(&self) -> OperandRefs<'_> {
        match self {
            Expr::Val(bv, _) => smallvec![bv as _],
            Expr::Var(var) => smallvec![var as _],
            Expr::Load(exp, _, _) => smallvec![&*exp as _],
            Expr::UnOp(_, exp) => smallvec![&*exp as _],
            Expr::BinOp(_, lexp, rexp) => smallvec![&*lexp as _, &*rexp as _],
            Expr::UnRel(_, exp) => smallvec![&*exp as _],
            Expr::BinRel(_, lexp, rexp) => smallvec![&*lexp as _, &*rexp as _],
            Expr::IfElse(cond, lexp, rexp) => smallvec![&*cond as _, &*lexp as _, &*rexp as _],
            Expr::Choice(sel, choices, default, _) => {
                let mut fst = smallvec![&*sel as _, &None::<BitVec> as _, &*default as _];
                for (option, value) in choices.iter() {
                    fst.push(option as _);
                    fst.push(value as _);
                }
                fst
            }
            Expr::Extract(exp, _, _) => smallvec![&*exp as _],
            Expr::ExtractHigh(exp, _) => smallvec![&*exp as _],
            Expr::ExtractLow(exp, _) => smallvec![&*exp as _],
            Expr::Concat(lexp, rexp) => smallvec![&*lexp as _, &*rexp as _],
            Expr::Intrinsic(_, ops, _) => ops.iter().map(|op| &*op as _).collect(),
            Expr::Cast(exp, typ) => smallvec![&*exp as _, &*typ as _],
        }
    }

    fn get_value(&self) -> Option<&BitVec> {
        self.value()
    }

    fn get_address(&self) -> Option<Address> {
        self.address_value()
    }

    fn get_variable(&self) -> Option<&Var> {
        self.variable()
    }

    fn get_lsb(&self) -> Option<u32> {
        match self {
            Expr::Extract(_, lsb, _) => Some(*lsb),
            Expr::ExtractLow(_, _) => Some(0),
            Expr::ExtractHigh(e, msbs) => Some(e.nbits() - msbs),
            _ => None,
        }
    }

    fn get_msb(&self) -> Option<u32> {
        match self {
            Expr::Extract(_, _, msb) => Some(*msb),
            Expr::ExtractLow(_, msb) => Some(*msb),
            Expr::ExtractHigh(e, _) => Some(e.nbits()),
            _ => None,
        }
    }

    fn get_name(&self) -> Option<Ustr> {
        match self {
            Expr::Intrinsic(name, _, _) => Some(name.clone()),
            _ => None,
        }
    }

    fn get_bits(&self) -> Option<u32> {
        Some(self.nbits())
    }

    fn get_nbytes(&self) -> Option<usize> {
        Some(self.nbits() as usize / 8)
    }

    fn address_space(&self) -> Option<AddressSpaceId> {
        match self {
            Expr::Var(v) => Some(v.space),
            _ => None,
        }
    }

    fn get_type(&self) -> Option<&Type> {
        match self {
            Expr::Cast(_, typ) => Some(&*typ),
            _ => None,
        }
    }
}

impl AsTerm for Stmt {
    fn op_type(&self) -> OpType {
        match self {
            Stmt::Assign(_, _) => OpType::ASSIGN,
            Stmt::Store(_, _, _, _) => OpType::STORE,
            Stmt::Branch(_) => OpType::BRANCH,
            Stmt::CBranch(_, _) => OpType::CBRANCH,
            Stmt::Call(_, _) => OpType::CALL,
            Stmt::Return(_) => OpType::RETURN,
            Stmt::Skip => OpType::SKIP,
            Stmt::Intrinsic(_, _) => OpType::INTRINSIC,
            Stmt::PointerHint(_) => OpType::INTRINSIC,
        }
    }

    fn op_class_type(&self) -> Option<ClassType> {
        Some(ClassType::STMT)
    }

    fn operand_refs(&self) -> OperandRefs<'_> {
        match self {
            Stmt::Assign(var, exp) => smallvec![var as _, &*exp as _],
            Stmt::Store(dexp, sexp, _, _) => smallvec![&*dexp as _, &*sexp as _],
            Stmt::Branch(bt) => smallvec![&*bt as _],
            Stmt::CBranch(cond, bt) => smallvec![&*cond as _, &*bt as _],
            Stmt::Call(bt, args) => std::iter::once(&*bt as _)
                .chain(args.iter().map(|arg| &*arg as _))
                .collect(),
            Stmt::Return(bt) => smallvec![&*bt as _],
            Stmt::Skip => smallvec![],
            Stmt::Intrinsic(_, ops) => ops.iter().map(|op| &*op as _).collect(),
            Stmt::PointerHint(var) => smallvec![var as _],
        }
    }

    fn get_variable(&self) -> Option<&Var> {
        match self {
            Stmt::Assign(var, _) => Some(var),
            _ => None,
        }
    }

    fn get_name(&self) -> Option<Ustr> {
        match self {
            Stmt::Intrinsic(name, _) => Some(*name),
            Stmt::PointerHint(_) => Some(*POINTER_HINT),
            _ => None,
        }
    }
}

impl AsTerm for Insn {
    fn op_type(&self) -> OpType {
        OpType::INSN
    }

    fn get_address(&self) -> Option<Address> {
        Some(self.address())
    }

    fn has_next_address(&self) -> bool {
        self.last_operation().map_or(false, |stmt| stmt.has_fall())
    }

    fn get_next_address(&self) -> Option<Address> {
        self.has_next_address()
            .then(|| self.address() + self.length())
    }

    fn operand_refs(&self) -> OperandRefs<'_> {
        self.operations.iter().map(|op| &*op as _).collect()
    }

    fn get_nbytes(&self) -> Option<usize> {
        Some(self.length() as usize)
    }
}

impl AsTerm for Location {
    fn op_type(&self) -> OpType {
        OpType::LOCATION
    }

    fn get_address(&self) -> Option<Address> {
        Some(self.address())
    }

    fn is_address(&self) -> bool {
        true
    }

    fn get_offset(&self) -> Option<u32> {
        Some(self.position() as u32)
    }
}

impl AsTerm for Type {
    fn op_type(&self) -> OpType {
        OpType::TYPE
    }

    fn op_sub_type(&self) -> Option<SubType> {
        Some(match self.kind() {
            TypeKind::Void => SubType::VOID,
            TypeKind::Bool => SubType::BOOL,
            TypeKind::Signed(_) => {
                if self.is_char() {
                    SubType::CHAR
                } else if self.is_char16() {
                    SubType::CHAR16
                } else if self.is_char32() {
                    SubType::CHAR32
                } else if self.is_wchar() {
                    SubType::WCHAR
                } else {
                    SubType::INT
                }
            }
            TypeKind::Unsigned(_) => {
                if self.is_unsigned_char() {
                    SubType::UNSIGNED_CHAR
                } else if self.is_wchar() {
                    SubType::UNSIGNED_WCHAR
                } else {
                    SubType::UNSIGNED_INT
                }
            }
            TypeKind::Float(_) => SubType::FLOAT,
            TypeKind::Pointer(_, _) => SubType::POINTER,
            TypeKind::ShiftedPointer(_, _, _) => SubType::SHIFTED_POINTER,
            TypeKind::Struct(_, _, _) => SubType::STRUCT,
            TypeKind::Union(_, _, _) => SubType::UNION,
            TypeKind::Function(_, _) => SubType::FUNC,
            TypeKind::Enum(_, _, _) => SubType::ENUM,
            TypeKind::Array(_, _) => {
                if self.is_incomplete_array() {
                    SubType::INCOMPLETE_ARRAY
                } else {
                    SubType::ARRAY
                }
            }
            TypeKind::Named(_, _) => SubType::TYPEDEF,
        })
    }

    fn get_type(&self) -> Option<&Type> {
        Some(self)
    }

    fn get_expanded_type(&self, db: &TypeDB) -> Option<Term<Type>> {
        Some(self.resolve(db))
    }

    fn get_name(&self) -> Option<Ustr> {
        Some(match self.kind() {
            TypeKind::Float(fmt) => Ustr::from(&format!("float{}", fmt.bits())),
            TypeKind::Array(typ, n) => Ustr::from(&format!("{}[{}]", typ.get_name()?, n)),
            TypeKind::Void => Ustr::from("void"),
            TypeKind::Bool => Ustr::from("bool"),
            TypeKind::Named(name, _) => name.clone(),
            TypeKind::Unsigned(_) if self.is_unsigned_char() => Ustr::from("unsigned char"),
            TypeKind::Unsigned(_) if self.is_wchar() => Ustr::from("unsigned wchar_t"),
            TypeKind::Unsigned(bits) => Ustr::from(&format!("uint{}_t", bits)),
            TypeKind::Signed(_) if self.is_char() => Ustr::from("char"),
            TypeKind::Signed(_) if self.is_char16() => Ustr::from("char16_t"),
            TypeKind::Signed(_) if self.is_char32() => Ustr::from("char32_t"),
            TypeKind::Signed(_) if self.is_wchar() => Ustr::from("wchar_t"),
            TypeKind::Signed(bits) => Ustr::from(&format!("int{}_t", bits)),
            TypeKind::Pointer(typ, _) => Ustr::from(&format!("{}*", typ.get_name()?)),
            TypeKind::ShiftedPointer(typ, off, _) => {
                Ustr::from(&format!("{}*@{}", typ.get_name()?, off))
            }
            TypeKind::Struct(name, _, _) => Ustr::from(&format!("struct {}", name)),
            TypeKind::Union(name, _, _) => Ustr::from(&format!("union {}", name)),
            TypeKind::Function(rtyp, args) => {
                let args = args
                    .iter()
                    .map(|arg| Some(format!("{}", arg.get_name()?)))
                    .collect::<Option<Vec<_>>>()?;
                Ustr::from(&format!("{}(*)({})", rtyp, args.join(", ")))
            }
            TypeKind::Enum(name, _, _) => Ustr::from(&format!("enum {}", name)),
        })
    }

    fn get_type_name(&self) -> Option<Ustr> {
        match self.kind() {
            TypeKind::Struct(name, _, _)
            | TypeKind::Union(name, _, _)
            | TypeKind::Enum(name, _, _)
            | TypeKind::Named(name, _) => Some(*name),
            _ => None,
        }
    }

    fn get_nbytes(&self) -> Option<usize> {
        Some(self.nbytes())
    }

    fn get_bits(&self) -> Option<u32> {
        Some(self.nbits())
    }

    fn operand_refs(&self) -> OperandRefs<'_> {
        match self.kind() {
            TypeKind::Float(_) | TypeKind::Void | TypeKind::Bool => {
                smallvec![]
            }
            TypeKind::Unsigned(bits) | TypeKind::Signed(bits) | TypeKind::Named(_, bits) => {
                smallvec![bits as _]
            }
            TypeKind::Array(typ, n) => smallvec![typ as _, n as _],
            TypeKind::Pointer(typ, bits) => smallvec![typ as _, bits as _],
            TypeKind::ShiftedPointer(typ, off, bits) => smallvec![typ as _, off as _, bits as _],
            TypeKind::Struct(_, fields, bits) => fields
                .iter()
                .map(|field| field as _)
                .chain(std::iter::once(bits as _))
                .collect(),
            TypeKind::Union(_, variants, bits) => variants
                .iter()
                .map(|variant| variant as _)
                .chain(std::iter::once(bits as _))
                .collect(),
            TypeKind::Function(rtyp, args) => std::iter::once(rtyp as _)
                .chain(args.iter().map(|arg| arg as _))
                .collect(),
            TypeKind::Enum(_, variants, bits) => variants
                .iter()
                .map(|variant| variant as _)
                .chain(std::iter::once(bits as _))
                .collect(),
        }
    }
}

impl AsTerm for EnumVariant {
    fn op_type(&self) -> OpType {
        OpType::ENUM_VARIANT
    }

    fn get_name(&self) -> Option<Ustr> {
        Some(self.name())
    }

    fn is_value(&self) -> bool {
        true
    }

    fn get_value(&self) -> Option<&BitVec> {
        Some(self.unsigned_value())
    }

    fn operand_refs(&self) -> OperandRefs<'_> {
        smallvec![self.unsigned_value() as _]
    }

    fn get_nbytes(&self) -> Option<usize> {
        Some(self.nbits() as usize / 8)
    }

    fn get_bits(&self) -> Option<u32> {
        Some(self.nbits())
    }
}

impl AsTerm for FunctionArg {
    fn op_type(&self) -> OpType {
        OpType::FUNC_ARG
    }

    fn get_name(&self) -> Option<Ustr> {
        self.name()
    }

    fn operand_refs(&self) -> OperandRefs<'_> {
        smallvec![self.type_() as _]
    }

    fn get_nbytes(&self) -> Option<usize> {
        Some(self.nbits() as usize / 8)
    }

    fn get_bits(&self) -> Option<u32> {
        Some(self.nbits())
    }
}

impl AsTerm for StructField {
    fn op_type(&self) -> OpType {
        OpType::STRUCT_FIELD
    }

    fn get_name(&self) -> Option<Ustr> {
        Some(self.name())
    }

    fn operand_refs(&self) -> OperandRefs<'_> {
        smallvec![self.type_() as _]
    }

    fn get_offset(&self) -> Option<u32> {
        Some(self.offset() as u32)
    }

    fn get_nbytes(&self) -> Option<usize> {
        Some(self.nbits() as usize / 8)
    }

    fn get_bits(&self) -> Option<u32> {
        Some(self.nbits())
    }
}

impl AsTerm for UnionVariant {
    fn op_type(&self) -> OpType {
        OpType::UNION_VARIANT
    }

    fn get_name(&self) -> Option<Ustr> {
        Some(self.name())
    }

    fn operand_refs(&self) -> OperandRefs<'_> {
        smallvec![self.type_() as _]
    }

    fn get_nbytes(&self) -> Option<usize> {
        Some(self.nbits() as usize / 8)
    }

    fn get_bits(&self) -> Option<u32> {
        Some(self.nbits())
    }
}

impl AsTerm for BranchTarget {
    fn op_type(&self) -> OpType {
        OpType::LOCATION
    }

    fn get_address(&self) -> Option<Address> {
        match self {
            BranchTarget::Location(loc) => Some(loc.address()),
            _ => None,
        }
    }

    fn get_offset(&self) -> Option<u32> {
        match self {
            BranchTarget::Location(loc) => Some(loc.position() as u32),
            _ => None,
        }
    }

    fn operand_refs(&self) -> OperandRefs<'_> {
        match self {
            BranchTarget::Location(loc) => smallvec![loc as _],
            BranchTarget::Computed(exp) => smallvec![&*exp as _],
            _ => smallvec![], // FIXME: this is not correct
        }
    }
}

impl AsTerm for Phi {
    fn op_type(&self) -> OpType {
        OpType::PHI
    }

    fn operand_refs(&self) -> OperandRefs<'_> {
        std::iter::once(self.target() as _)
            .chain(self.sources().iter().map(|var| var as _))
            .collect()
    }

    fn get_bits(&self) -> Option<u32> {
        Some(self.target().nbits())
    }

    fn get_variable(&self) -> Option<&Var> {
        Some(self.target())
    }
}

impl AsTerm for CodeBlock {
    fn op_type(&self) -> OpType {
        OpType::BLOCK
    }

    fn get_address(&self) -> Option<Address> {
        Some(self.address())
    }

    fn has_next_address(&self) -> bool {
        self.last_operation().has_fall()
    }

    fn get_next_address(&self) -> Option<Address> {
        self.has_next_address().then(|| self.address() + self.len())
    }

    fn operand_refs(&self) -> OperandRefs<'_> {
        self.phis()
            .iter()
            .map(|phi| phi as _)
            .chain(self.insns().iter().map(|insn| insn as _))
            .collect()
    }

    fn get_nbytes(&self) -> Option<usize> {
        Some(self.len())
    }

    fn get_bits(&self) -> Option<u32> {
        Some(self.len() as u32 * 8)
    }
}
