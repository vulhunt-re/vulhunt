use fugue::bv::BitVec;
use thiserror::Error;
use ustr::Ustr;

use super::{IRContext, StateError};
use crate::cio::TypeDB;
use crate::ir::{BitSize, Term, Type, Var};
use crate::lifter::DefaultPrototype;
use crate::Project;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    State(#[from] StateError),
    #[error("resolution procedure could not be applied to type {0}")]
    UnexpectedType(Term<Type>),
    #[error("unsupported calling convention")]
    UnsupportedConvention,
}

pub type ResolverError = Error;

pub struct CallSiteResolver {
    typedb: TypeDB,
    addr_bits: u32,
    prototype: DefaultPrototype,
}

impl CallSiteResolver {
    pub fn new(project: &Project) -> Self {
        Self {
            typedb: project.type_db().clone(),
            addr_bits: project.lifter().address_bits(),
            prototype: project.lifter().default_prototype(),
        }
    }

    pub fn visit_args<V>(
        &self,
        context: &Box<dyn IRContext>,
        ftyp: &Term<Type>,
        visitor: &mut V,
    ) -> Result<(), Error>
    where
        V: DataResolver,
    {
        let nftyp = ftyp.resolve(&self.typedb);
        let fargs = nftyp
            .function_args()
            .ok_or_else(|| Error::UnexpectedType(ftyp.clone()))?;

        let stack_pointer = context.read_stack_pointer()?;

        for (i, arg) in fargs.iter().enumerate() {
            if arg.nbits() <= self.addr_bits {
                let argn = self
                    .prototype
                    .resolved_input(i, stack_pointer)
                    .ok_or_else(|| Error::UnsupportedConvention)?;
                let atyp = arg.type_().resolve(&self.typedb);
                let name = arg.name();
                visitor.resolve_named(context, &self.typedb, argn, name, atyp)?;
            } else {
                // we can't use the default resolver for this case
                tracing::trace!(
                    "unsupported convention for argument {i} with type {}",
                    arg.type_()
                );
                return Err(Error::UnsupportedConvention);
            }
        }

        Ok(())
    }
}

pub trait DataResolver {
    fn resolve(
        &mut self,
        context: &Box<dyn IRContext>,
        typedb: &TypeDB,
        var: Var,
        typ: Term<Type>,
    ) -> Result<(), ResolverError>;

    fn resolve_named(
        &mut self,
        context: &Box<dyn IRContext>,
        typedb: &TypeDB,
        var: Var,
        _name: Option<Ustr>,
        typ: Term<Type>,
    ) -> Result<(), ResolverError> {
        self.resolve(context, typedb, var, typ)
    }
}

#[derive(Default)]
pub struct DefaultResolver {
    resolved: Vec<BitVec>,
}

impl DefaultResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resolved(&self) -> &[BitVec] {
        &self.resolved
    }

    pub fn resolved_mut(&mut self) -> &mut Vec<BitVec> {
        &mut self.resolved
    }
}

impl DataResolver for DefaultResolver {
    fn resolve(
        &mut self,
        context: &Box<dyn IRContext>,
        _typedb: &TypeDB,
        var: Var,
        _typ: Term<Type>,
    ) -> Result<(), ResolverError> {
        self.resolved.push(context.read_var(&var)?);
        Ok(())
    }
}
