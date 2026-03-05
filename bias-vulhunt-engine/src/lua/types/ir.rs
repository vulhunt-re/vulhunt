use std::ops::Deref;

use bias_core::fugue::ir::AddressSpaceId;
use bias_core::ir::term::traits::{AsTerm, ClassType, OpType, SubType};
use bias_core::ir::{Address, BitSize, BitVec, Var, Variable as _};

use mlua::prelude::*;
use ustr::Ustr;

use crate::lua::api::AddressValue;
use crate::lua::types::BitVec as LuaBitVec;

#[derive(Clone, Copy, FromLua)]
#[repr(transparent)]
pub struct AddressSpace(AddressSpaceId);

impl From<AddressSpaceId> for AddressSpace {
    fn from(space_id: AddressSpaceId) -> Self {
        AddressSpace(space_id)
    }
}

impl Deref for AddressSpace {
    type Target = AddressSpaceId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl LuaUserData for AddressSpace {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("is_constant", |_, this, ()| Ok(this.is_constant()));
        methods.add_method("is_default", |_, this, ()| Ok(this.is_default()));
        methods.add_method("is_register", |_, this, ()| Ok(this.is_register()));
        methods.add_method("is_temporary", |_, this, ()| Ok(this.is_unique()));
        methods.add_method("index", |_, this, ()| Ok(this.0.index()));
    }
}

#[derive(Clone, Copy, FromLua)]
#[repr(transparent)]
pub struct IRVar(Var);

impl From<Var> for IRVar {
    fn from(var: Var) -> Self {
        Self(var)
    }
}

impl From<&Var> for IRVar {
    fn from(var: &Var) -> Self {
        Self(*var)
    }
}

impl Deref for IRVar {
    type Target = Var;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl LuaUserData for IRVar {
    fn add_fields<F: LuaUserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("num_bits", |_, this| Ok(this.nbits()));
        fields.add_field_method_get("num_bytes", |_, this| Ok(this.nbits().div_ceil(8) as usize));

        fields.add_field_method_get("address_space", |_, this| {
            Ok(AddressSpace::from(this.space()))
        });

        fields.add_field_method_get("address", |lua, this| {
            this.address()
                .map(|addr| AddressValue::new_ser(lua, addr))
                .transpose()
        });

        fields.add_field_method_get("value", |lua, this| {
            if this.space().is_constant() {
                return Ok(Some(
                    LuaBitVec::from(BitVec::from_u64(this.offset(), this.nbits() as _))
                        .into_lua(lua)?,
                ));
            }

            if this.space().is_default() {
                let addr = AddressValue::new_ser(lua, Address::from(this.offset()))?;
                return Ok(Some(addr));
            }

            Ok(None)
        });

        fields.add_field_method_get("offset", |_, this| {
            Ok(LuaValue::Integer(this.offset() as LuaInteger))
        });

        fields.add_field_method_get("generation", |_, this| Ok(this.generation()));
    }

    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("is_temporary", |_, this, ()| Ok(this.is_temporary()));
        methods.add_method("is_register", |_, this, ()| Ok(this.is_register()));
        methods.add_method("is_address", |_, this, ()| Ok(this.is_address()));
        methods.add_method("is_constant", |_, this, ()| Ok(this.space().is_constant()));

        methods.add_meta_method(LuaMetaMethod::ToString, |_, this, ()| {
            Ok(format!("{}", this.0))
        });

        methods.add_meta_method(LuaMetaMethod::Eq, |_, this, other: IRVar| {
            Ok(this.0 == other.0)
        });
        methods.add_meta_method(LuaMetaMethod::Lt, |_, this, other: IRVar| {
            Ok(this.0 < other.0)
        });
        methods.add_meta_method(LuaMetaMethod::Le, |_, this, other: IRVar| {
            Ok(this.0 <= other.0)
        });
    }
}

#[derive(Clone, FromLua)]
#[repr(transparent)]
pub struct IRTerm(Box<dyn AsTerm>);

impl<T> From<T> for IRTerm
where
    T: AsTerm + 'static,
{
    fn from(term: T) -> Self {
        Self::new(term)
    }
}

impl Deref for IRTerm {
    type Target = dyn AsTerm;

    fn deref(&self) -> &Self::Target {
        self.as_term()
    }
}

impl IRTerm {
    pub fn new(term: impl AsTerm + 'static) -> Self {
        IRTerm(Box::new(term))
    }

    pub fn as_term(&self) -> &dyn AsTerm {
        self.0.as_ref()
    }

    pub fn args(&self) -> Vec<IRTerm> {
        self.as_term().operands().into_iter().map(Self).collect()
    }

    pub fn type_args(&self, target: OpType) -> Vec<IRTerm> {
        self.type_args_with(target, 0)
    }

    pub fn type_args_with(&self, target: OpType, offset: usize) -> Vec<IRTerm> {
        if self.as_term().op_type() != OpType::TYPE {
            return Vec::with_capacity(0);
        }

        let opnds = self.as_term().operands();

        if opnds
            .get(offset)
            .is_some_and(|first| first.op_type() == target)
        {
            return opnds
                .into_iter()
                .skip(offset)
                .take_while(|op| op.op_type() == target)
                .map(Self)
                .collect();
        }

        Vec::with_capacity(0)
    }

    pub fn to_lua_value(&self, lua: &Lua) -> LuaResult<Option<LuaValue>> {
        if let Some(shift_offset) = self.as_term().get_shift_offset() {
            return Ok(Some(LuaValue::Integer(shift_offset as LuaInteger)));
        }

        if let Some(offset) = self.as_term().get_offset() {
            return Ok(Some(LuaValue::Integer(offset as LuaInteger)));
        }

        self.as_term()
            .get_value()
            .map(|val| {
                let value = LuaBitVec::from(val.to_owned());
                value.into_lua(lua)
            })
            .transpose()
    }

    pub fn register(lua: &Lua) -> LuaResult<()> {
        lua.globals()
            .set("AddressSpace", lua.create_proxy::<AddressSpace>()?)?;
        lua.globals()
            .set("IRTermKind", lua.create_proxy::<IRTermKind>()?)?;
        lua.globals()
            .set("IRTermSubKind", lua.create_proxy::<IRTermSubKind>()?)?;
        lua.globals()
            .set("IRTermClassKind", lua.create_proxy::<IRTermClassKind>()?)?;
        lua.globals().set("IRVar", lua.create_proxy::<IRVar>()?)?;
        lua.globals().set("IRTerm", lua.create_proxy::<IRTerm>()?)?;
        Ok(())
    }
}

#[derive(Clone, Copy, FromLua)]
#[repr(transparent)]
pub struct IRTermKind(OpType);

impl<T> From<T> for IRTermKind
where
    T: Into<OpType>,
{
    fn from(op_type: T) -> Self {
        IRTermKind::new(op_type.into())
    }
}

impl Deref for IRTermKind {
    type Target = OpType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IRTermKind {
    pub fn new(op_type: OpType) -> Self {
        IRTermKind(op_type)
    }
}

#[derive(Clone, Copy, FromLua)]
#[repr(transparent)]
pub struct IRTermSubKind(SubType);

impl<T> From<T> for IRTermSubKind
where
    T: Into<SubType>,
{
    fn from(op_type: T) -> Self {
        IRTermSubKind::new(op_type.into())
    }
}

impl Deref for IRTermSubKind {
    type Target = SubType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IRTermSubKind {
    pub fn new(sub_type: SubType) -> Self {
        IRTermSubKind(sub_type)
    }
}

#[derive(Clone, Copy, FromLua)]
#[repr(transparent)]
pub struct IRTermClassKind(ClassType);

impl<T> From<T> for IRTermClassKind
where
    T: Into<ClassType>,
{
    fn from(op_type: T) -> Self {
        IRTermClassKind::new(op_type.into())
    }
}

impl Deref for IRTermClassKind {
    type Target = ClassType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IRTermClassKind {
    pub fn new(sub_type: ClassType) -> Self {
        IRTermClassKind(sub_type)
    }
}

impl LuaUserData for IRTerm {
    fn add_fields<F: LuaUserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("address", |lua, this| {
            this.as_term()
                .get_address()
                .map(|addr| AddressValue::new_ser(lua, addr))
                .transpose()
        });

        fields.add_field_method_get("next_address", |lua, this| {
            this.as_term()
                .get_next_address()
                .map(|addr| AddressValue::new_ser(lua, addr))
                .transpose()
        });

        fields.add_field_method_get("name", |_, this| {
            Ok(this.as_term().get_name().as_ref().map(Ustr::to_owned))
        });

        fields.add_field_method_get("num_bits", |_, this| Ok(this.as_term().get_bits()));
        fields.add_field_method_get("num_bytes", |_, this| Ok(this.as_term().get_nbytes()));

        fields.add_field_method_get("type", |_, this| {
            Ok(this
                .as_term()
                .get_type()
                .map(|typ| Self::new(typ.to_owned())))
        });

        fields.add_field_method_get("type_name", |_, this| {
            Ok(this.as_term().get_type_name().as_ref().map(Ustr::to_owned))
        });

        // decompose operands/fields/...
        fields.add_field_method_get("terms", |_, this| Ok(this.args()));

        fields.add_field_method_get("variable", |_, this| {
            Ok(this.as_term().get_variable().map(IRVar::from))
        });

        fields.add_field_method_get("value", |lua, this| this.to_lua_value(lua));

        fields.add_field_method_get("lsb", |_, this| Ok(this.as_term().get_lsb()));
        fields.add_field_method_get("msb", |_, this| Ok(this.as_term().get_msb()));

        fields.add_field_method_get("kind", |_, this| {
            Ok(IRTermKind::from(this.as_term().op_type()))
        });
        fields.add_field_method_get("sub_kind", |_, this| {
            Ok(this.as_term().op_sub_type().map(IRTermSubKind::from))
        });
        fields.add_field_method_get("class_kind", |_, this| {
            Ok(this.as_term().op_class_type().map(IRTermClassKind::from))
        });

        fields.add_field_method_get("insns", |_, this| {
            Ok(matches!(this.op_type(), OpType::BLOCK).then(|| this.args()))
        });
        fields.add_field_method_get("stmts", |_, this| {
            Ok(matches!(this.op_type(), OpType::INSN | OpType::PHI).then(|| this.args()))
        });
        fields.add_field_method_get("operands", |_, this| {
            Ok((matches!(this.op_type(), OpType::INSN | OpType::PHI)
                || matches!(
                    this.op_class_type(),
                    Some(ClassType::EXPR | ClassType::STMT)
                ))
            .then(|| this.args()))
        });

        fields.add_field_method_get("struct_fields", |_, this| {
            Ok(this.type_args(OpType::STRUCT_FIELD))
        });
        fields.add_field_method_get("function_arguments", |_, this| {
            Ok(this.type_args_with(OpType::FUNC_ARG, 1))
        });
        fields.add_field_method_get("function_return_type", |_, this| {
            let term = this.as_term();
            if term.op_type() == OpType::TYPE && term.op_sub_type() != Some(SubType::FUNC) {
                return Ok(None);
            }
            Ok(term.operands().into_iter().next().map(Self))
        });
        fields.add_field_method_get("enum_variants", |_, this| {
            Ok(this.type_args(OpType::ENUM_VARIANT))
        });
        fields.add_field_method_get("union_variants", |_, this| {
            Ok(this.type_args(OpType::UNION_VARIANT))
        });
    }

    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("is_address", |_, this, ()| Ok(this.as_term().is_address()));

        methods.add_method("has_next_address", |_, this, ()| {
            Ok(this.as_term().has_next_address())
        });

        methods.add_method("is_variable", |_, this, ()| {
            Ok(this.as_term().is_variable())
        });

        methods.add_method("is_value", |_, this, ()| Ok(this.as_term().is_value()));

        methods.add_method("to_bitvec", |lua, this, ()| this.to_lua_value(lua));

        methods.add_method("is_offset", |_, this, ()| Ok(this.as_term().is_offset()));

        methods.add_method("is_shift_offset", |_, this, ()| {
            Ok(this.as_term().is_shift_offset())
        });
    }
}

impl LuaUserData for IRTermKind {
    fn add_fields<F: LuaUserDataFields<Self>>(fields: &mut F) {
        fields.add_field_function_get("BLOCK", |_, _| Ok(Self(OpType::BLOCK)));
        fields.add_field_function_get("INSN", |_, _| Ok(Self(OpType::INSN)));
        fields.add_field_function_get("PHI", |_, _| Ok(Self(OpType::PHI)));

        // Statements
        fields.add_field_function_get("ASSIGN", |_, _| Ok(Self(OpType::ASSIGN)));
        fields.add_field_function_get("STORE", |_, _| Ok(Self(OpType::STORE)));
        fields.add_field_function_get("BRANCH", |_, _| Ok(Self(OpType::BRANCH)));
        fields.add_field_function_get("CBRANCH", |_, _| Ok(Self(OpType::CBRANCH)));
        fields.add_field_function_get("CALL", |_, _| Ok(Self(OpType::CALL)));
        fields.add_field_function_get("RETURN", |_, _| Ok(Self(OpType::RETURN)));
        fields.add_field_function_get("SKIP", |_, _| Ok(Self(OpType::SKIP)));
        fields.add_field_function_get("INTRINSIC", |_, _| Ok(Self(OpType::INTRINSIC)));

        // Bit size/offset
        fields.add_field_function_get("OFFSET", |_, _| Ok(Self(OpType::OFFSET)));

        // Location
        fields.add_field_function_get("LOCATION", |_, _| Ok(Self(OpType::LOCATION)));

        // Expressions
        fields.add_field_function_get("VAR", |_, _| Ok(Self(OpType::VAR)));
        fields.add_field_function_get("VAL", |_, _| Ok(Self(OpType::VAL)));

        fields.add_field_function_get("LOAD", |_, _| Ok(Self(OpType::LOAD)));
        fields.add_field_function_get("CAST", |_, _| Ok(Self(OpType::CAST)));
        fields.add_field_function_get("IFELSE", |_, _| Ok(Self(OpType::IFELSE)));
        fields.add_field_function_get("EXTRACT", |_, _| Ok(Self(OpType::EXTRACT)));
        fields.add_field_function_get("CONCAT", |_, _| Ok(Self(OpType::CONCAT)));
        fields.add_field_function_get("CHOICE", |_, _| Ok(Self(OpType::CHOICE)));

        // UnRel
        fields.add_field_function_get("NAN", |_, _| Ok(Self(OpType::NAN)));

        // UnOp
        fields.add_field_function_get("NOT", |_, _| Ok(Self(OpType::NOT)));
        fields.add_field_function_get("NEG", |_, _| Ok(Self(OpType::NEG)));
        fields.add_field_function_get("ABS", |_, _| Ok(Self(OpType::ABS)));
        fields.add_field_function_get("SQRT", |_, _| Ok(Self(OpType::SQRT)));
        fields.add_field_function_get("CEILING", |_, _| Ok(Self(OpType::CEILING)));
        fields.add_field_function_get("FLOOR", |_, _| Ok(Self(OpType::FLOOR)));
        fields.add_field_function_get("ROUND", |_, _| Ok(Self(OpType::ROUND)));
        fields.add_field_function_get("POPCOUNT", |_, _| Ok(Self(OpType::POPCOUNT)));

        // BinOp
        fields.add_field_function_get("AND", |_, _| Ok(Self(OpType::AND)));
        fields.add_field_function_get("OR", |_, _| Ok(Self(OpType::OR)));
        fields.add_field_function_get("XOR", |_, _| Ok(Self(OpType::XOR)));
        fields.add_field_function_get("ADD", |_, _| Ok(Self(OpType::ADD)));
        fields.add_field_function_get("SUB", |_, _| Ok(Self(OpType::SUB)));
        fields.add_field_function_get("DIV", |_, _| Ok(Self(OpType::DIV)));
        fields.add_field_function_get("SDIV", |_, _| Ok(Self(OpType::SDIV)));
        fields.add_field_function_get("MUL", |_, _| Ok(Self(OpType::MUL)));
        fields.add_field_function_get("REM", |_, _| Ok(Self(OpType::REM)));
        fields.add_field_function_get("SREM", |_, _| Ok(Self(OpType::SREM)));
        fields.add_field_function_get("SHL", |_, _| Ok(Self(OpType::SHL)));
        fields.add_field_function_get("SAR", |_, _| Ok(Self(OpType::SAR)));
        fields.add_field_function_get("SHR", |_, _| Ok(Self(OpType::SHR)));

        // BinRel
        fields.add_field_function_get("EQ", |_, _| Ok(Self(OpType::EQ)));
        fields.add_field_function_get("NEQ", |_, _| Ok(Self(OpType::NEQ)));
        fields.add_field_function_get("LT", |_, _| Ok(Self(OpType::LT)));
        fields.add_field_function_get("LE", |_, _| Ok(Self(OpType::LE)));
        fields.add_field_function_get("SLT", |_, _| Ok(Self(OpType::SLT)));
        fields.add_field_function_get("SLE", |_, _| Ok(Self(OpType::SLE)));

        fields.add_field_function_get("SBORROW", |_, _| Ok(Self(OpType::SBORROW)));
        fields.add_field_function_get("CARRY", |_, _| Ok(Self(OpType::CARRY)));
        fields.add_field_function_get("SCARRY", |_, _| Ok(Self(OpType::SCARRY)));

        // Type
        fields.add_field_function_get("TYPE", |_, _| Ok(Self(OpType::TYPE)));
        fields.add_field_function_get("STRUCT_FIELD", |_, _| Ok(Self(OpType::STRUCT_FIELD)));
        fields.add_field_function_get("FUNC_ARG", |_, _| Ok(Self(OpType::FUNC_ARG)));
        fields.add_field_function_get("ENUM_VARIANT", |_, _| Ok(Self(OpType::ENUM_VARIANT)));
        fields.add_field_function_get("UNION_VARIANT", |_, _| Ok(Self(OpType::UNION_VARIANT)));
    }

    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("is_block", |_, this, ()| Ok(this.0 == OpType::BLOCK));
        methods.add_method("is_insn", |_, this, ()| Ok(this.0 == OpType::INSN));
        methods.add_method("is_phi", |_, this, ()| Ok(this.0 == OpType::PHI));

        methods.add_method("is_assign", |_, this, ()| Ok(this.0 == OpType::ASSIGN));
        methods.add_method("is_store", |_, this, ()| Ok(this.0 == OpType::STORE));
        methods.add_method("is_branch", |_, this, ()| Ok(this.0 == OpType::BRANCH));
        methods.add_method("is_cbranch", |_, this, ()| Ok(this.0 == OpType::CBRANCH));
        methods.add_method("is_call", |_, this, ()| Ok(this.0 == OpType::CALL));
        methods.add_method("is_return", |_, this, ()| Ok(this.0 == OpType::RETURN));
        methods.add_method("is_skip", |_, this, ()| Ok(this.0 == OpType::SKIP));
        methods.add_method(
            "is_intrinsic",
            |_, this, ()| Ok(this.0 == OpType::INTRINSIC),
        );

        methods.add_method("is_offset", |_, this, ()| Ok(this.0 == OpType::OFFSET));
        methods.add_method("is_location", |_, this, ()| Ok(this.0 == OpType::LOCATION));

        methods.add_method("is_var", |_, this, ()| Ok(this.0 == OpType::VAR));
        methods.add_method("is_val", |_, this, ()| Ok(this.0 == OpType::VAL));
        methods.add_method("is_load", |_, this, ()| Ok(this.0 == OpType::LOAD));
        methods.add_method("is_cast", |_, this, ()| Ok(this.0 == OpType::CAST));
        methods.add_method("is_ifelse", |_, this, ()| Ok(this.0 == OpType::IFELSE));
        methods.add_method("is_extract", |_, this, ()| Ok(this.0 == OpType::EXTRACT));
        methods.add_method("is_concat", |_, this, ()| Ok(this.0 == OpType::CONCAT));
        methods.add_method("is_choice", |_, this, ()| Ok(this.0 == OpType::CHOICE));

        methods.add_method("is_nan", |_, this, ()| Ok(this.0 == OpType::NAN));

        methods.add_method("is_not", |_, this, ()| Ok(this.0 == OpType::NOT));
        methods.add_method("is_neg", |_, this, ()| Ok(this.0 == OpType::NEG));
        methods.add_method("is_abs", |_, this, ()| Ok(this.0 == OpType::ABS));
        methods.add_method("is_sqrt", |_, this, ()| Ok(this.0 == OpType::SQRT));
        methods.add_method("is_ceiling", |_, this, ()| Ok(this.0 == OpType::CEILING));
        methods.add_method("is_floor", |_, this, ()| Ok(this.0 == OpType::FLOOR));
        methods.add_method("is_round", |_, this, ()| Ok(this.0 == OpType::ROUND));
        methods.add_method("is_popcount", |_, this, ()| Ok(this.0 == OpType::POPCOUNT));

        methods.add_method("is_and", |_, this, ()| Ok(this.0 == OpType::AND));
        methods.add_method("is_or", |_, this, ()| Ok(this.0 == OpType::OR));
        methods.add_method("is_xor", |_, this, ()| Ok(this.0 == OpType::XOR));
        methods.add_method("is_add", |_, this, ()| Ok(this.0 == OpType::ADD));
        methods.add_method("is_sub", |_, this, ()| Ok(this.0 == OpType::SUB));
        methods.add_method("is_div", |_, this, ()| Ok(this.0 == OpType::DIV));
        methods.add_method("is_signed_div", |_, this, ()| Ok(this.0 == OpType::SDIV));
        methods.add_method("is_mul", |_, this, ()| Ok(this.0 == OpType::MUL));
        methods.add_method("is_rem", |_, this, ()| Ok(this.0 == OpType::REM));
        methods.add_method("is_signed_rem", |_, this, ()| Ok(this.0 == OpType::SREM));
        methods.add_method("is_shl", |_, this, ()| Ok(this.0 == OpType::SHL));
        methods.add_method("is_signed_shr", |_, this, ()| Ok(this.0 == OpType::SAR));
        methods.add_method("is_shr", |_, this, ()| Ok(this.0 == OpType::SHR));

        methods.add_method("is_eq", |_, this, ()| Ok(this.0 == OpType::EQ));
        methods.add_method("is_neq", |_, this, ()| Ok(this.0 == OpType::NEQ));
        methods.add_method("is_lt", |_, this, ()| Ok(this.0 == OpType::LT));
        methods.add_method("is_le", |_, this, ()| Ok(this.0 == OpType::LE));
        methods.add_method("is_signed_lt", |_, this, ()| Ok(this.0 == OpType::SLT));
        methods.add_method("is_signed_le", |_, this, ()| Ok(this.0 == OpType::SLE));

        methods.add_method("is_signed_borrow", |_, this, ()| {
            Ok(this.0 == OpType::SBORROW)
        });
        methods.add_method("is_carry", |_, this, ()| Ok(this.0 == OpType::CARRY));
        methods.add_method(
            "is_signed_carry",
            |_, this, ()| Ok(this.0 == OpType::SCARRY),
        );

        methods.add_method("is_type", |_, this, ()| Ok(this.0 == OpType::TYPE));
        methods.add_method("is_struct_field", |_, this, ()| {
            Ok(this.0 == OpType::STRUCT_FIELD)
        });
        methods.add_method("is_function_argument", |_, this, ()| {
            Ok(this.0 == OpType::FUNC_ARG)
        });
        methods.add_method("is_enum_variant", |_, this, ()| {
            Ok(this.0 == OpType::ENUM_VARIANT)
        });
        methods.add_method("is_union_variant", |_, this, ()| {
            Ok(this.0 == OpType::UNION_VARIANT)
        });

        methods.add_meta_method(LuaMetaMethod::ToString, |_, this, ()| {
            // TODO(slt): add Display for OpType
            let repr = match this.0 {
                OpType::BLOCK => "BLOCK",
                OpType::INSN => "INSN",
                OpType::PHI => "PHI",

                // Statements
                OpType::ASSIGN => "ASSIGN",
                OpType::STORE => "STORE",
                OpType::BRANCH => "BRANCH",
                OpType::CBRANCH => "CBRANCH",
                OpType::CALL => "CALL",
                OpType::RETURN => "RETURN",
                OpType::SKIP => "SKIP",
                OpType::INTRINSIC => "INTRINSIC",

                // Bit size/offset
                OpType::OFFSET => "OFFSET",

                // Location
                OpType::LOCATION => "LOCATION",

                // Expressions
                OpType::VAR => "VAR",
                OpType::VAL => "VAL",

                OpType::LOAD => "LOAD",
                OpType::CAST => "CAST",
                OpType::IFELSE => "IFELSE",
                OpType::EXTRACT => "EXTRACT",
                OpType::CONCAT => "CONCAT",
                OpType::CHOICE => "CHOICE",

                // UnRel
                OpType::NAN => "NAN",

                // UnOp
                OpType::NOT => "NOT",
                OpType::NEG => "NEG",
                OpType::ABS => "ABS",
                OpType::SQRT => "SQRT",
                OpType::CEILING => "CEILING",
                OpType::FLOOR => "FLOOR",
                OpType::ROUND => "ROUND",
                OpType::POPCOUNT => "POPCOUNT",

                // BinOp
                OpType::AND => "AND",
                OpType::OR => "OR",
                OpType::XOR => "XOR",
                OpType::ADD => "ADD",
                OpType::SUB => "SUB",
                OpType::DIV => "DIV",
                OpType::SDIV => "SDIV",
                OpType::MUL => "MUL",
                OpType::REM => "REM",
                OpType::SREM => "SREM",
                OpType::SHL => "SHL",
                OpType::SAR => "SAR",
                OpType::SHR => "SHR",

                // BinRel
                OpType::EQ => "EQ",
                OpType::NEQ => "NEQ",
                OpType::LT => "LT",
                OpType::LE => "LE",
                OpType::SLT => "SLT",
                OpType::SLE => "SLE",

                OpType::SBORROW => "SBORROW",
                OpType::CARRY => "CARRY",
                OpType::SCARRY => "SCARRY",

                // Type
                OpType::TYPE => "TYPE",
                OpType::STRUCT_FIELD => "STRUCT_FIELD",
                OpType::FUNC_ARG => "FUNC_ARG",
                OpType::ENUM_VARIANT => "ENUM_VARIANT",
                OpType::UNION_VARIANT => "UNION_VARIANT",
            };

            Ok(repr.to_owned())
        });

        methods.add_meta_method(LuaMetaMethod::Eq, |_, this, other: IRTermKind| {
            Ok(this.0 == other.0)
        });
        methods.add_meta_method(LuaMetaMethod::Lt, |_, this, other: IRTermKind| {
            Ok(this.0 < other.0)
        });
        methods.add_meta_method(LuaMetaMethod::Le, |_, this, other: IRTermKind| {
            Ok(this.0 <= other.0)
        });
    }
}

impl LuaUserData for IRTermSubKind {
    fn add_fields<F: LuaUserDataFields<Self>>(fields: &mut F) {
        fields.add_field_function_get("VOID", |_, _| Ok(Self(SubType::VOID)));
        fields.add_field_function_get("BOOL", |_, _| Ok(Self(SubType::BOOL)));
        fields.add_field_function_get("CHAR", |_, _| Ok(Self(SubType::CHAR)));
        fields.add_field_function_get("UNSIGNED_CHAR", |_, _| Ok(Self(SubType::UNSIGNED_CHAR)));
        fields.add_field_function_get("CHAR16", |_, _| Ok(Self(SubType::CHAR16)));
        fields.add_field_function_get("CHAR32", |_, _| Ok(Self(SubType::CHAR32)));
        fields.add_field_function_get("WCHAR", |_, _| Ok(Self(SubType::WCHAR)));
        fields.add_field_function_get("UNSIGNED_WCHAR", |_, _| Ok(Self(SubType::UNSIGNED_WCHAR)));
        fields.add_field_function_get("INT", |_, _| Ok(Self(SubType::INT)));
        fields.add_field_function_get("UNSIGNED_INT", |_, _| Ok(Self(SubType::UNSIGNED_INT)));
        fields.add_field_function_get("FLOAT", |_, _| Ok(Self(SubType::FLOAT)));
        fields.add_field_function_get("POINTER", |_, _| Ok(Self(SubType::POINTER)));
        fields.add_field_function_get("SHIFTED_POINTER", |_, _| Ok(Self(SubType::SHIFTED_POINTER)));
        fields.add_field_function_get("STRUCT", |_, _| Ok(Self(SubType::STRUCT)));
        fields.add_field_function_get("FUNC", |_, _| Ok(Self(SubType::FUNC)));
        fields.add_field_function_get("ENUM", |_, _| Ok(Self(SubType::ENUM)));
        fields.add_field_function_get("UNION", |_, _| Ok(Self(SubType::UNION)));
        fields.add_field_function_get("ARRAY", |_, _| Ok(Self(SubType::ARRAY)));
        fields.add_field_function_get("INCOMPLETE_ARRAY", |_, _| {
            Ok(Self(SubType::INCOMPLETE_ARRAY))
        });
        fields.add_field_function_get("TYPEDEF", |_, _| Ok(Self(SubType::TYPEDEF)));
    }

    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(LuaMetaMethod::ToString, |_, this, ()| {
            let repr = match this.0 {
                SubType::VOID => "VOID",
                SubType::BOOL => "BOOL",
                SubType::CHAR => "CHAR",
                SubType::UNSIGNED_CHAR => "UNSIGNED_CHAR",
                SubType::CHAR16 => "CHAR16",
                SubType::CHAR32 => "CHAR32",
                SubType::WCHAR => "WCHAR",
                SubType::UNSIGNED_WCHAR => "UNSIGNED_WCHAR",
                SubType::INT => "INT",
                SubType::UNSIGNED_INT => "UNSIGNED_INT",
                SubType::FLOAT => "FLOAT",
                SubType::POINTER => "POINTER",
                SubType::SHIFTED_POINTER => "SHIFTED_POINTER",
                SubType::STRUCT => "STRUCT",
                SubType::FUNC => "FUNC",
                SubType::ENUM => "ENUM",
                SubType::UNION => "UNION",
                SubType::ARRAY => "ARRAY",
                SubType::INCOMPLETE_ARRAY => "INCOMPLETE_ARRAY",
                SubType::TYPEDEF => "TYPEDEF",
            };

            Ok(repr.to_owned())
        });

        methods.add_meta_method(LuaMetaMethod::Eq, |_, this, other: IRTermSubKind| {
            Ok(this.0 == other.0)
        });
        methods.add_meta_method(LuaMetaMethod::Lt, |_, this, other: IRTermSubKind| {
            Ok(this.0 < other.0)
        });
        methods.add_meta_method(LuaMetaMethod::Le, |_, this, other: IRTermSubKind| {
            Ok(this.0 <= other.0)
        });
    }
}

impl LuaUserData for IRTermClassKind {
    fn add_fields<F: LuaUserDataFields<Self>>(fields: &mut F) {
        fields.add_field_function_get("STMT", |_, _| Ok(Self(ClassType::STMT)));
        fields.add_field_function_get("EXPR", |_, _| Ok(Self(ClassType::EXPR)));
    }

    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(LuaMetaMethod::ToString, |_, this, ()| {
            let repr = match this.0 {
                ClassType::STMT => "STMT",
                ClassType::EXPR => "EXPR",
            };

            Ok(repr.to_owned())
        });

        methods.add_meta_method(LuaMetaMethod::Eq, |_, this, other: IRTermClassKind| {
            Ok(this.0 == other.0)
        });
        methods.add_meta_method(LuaMetaMethod::Lt, |_, this, other: IRTermClassKind| {
            Ok(this.0 < other.0)
        });
        methods.add_meta_method(LuaMetaMethod::Le, |_, this, other: IRTermClassKind| {
            Ok(this.0 <= other.0)
        });
    }
}
