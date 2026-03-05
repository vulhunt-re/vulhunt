pub use ahash::RandomState as AHashRandomState;
pub use fugue::arch::ArchitectureDef;
pub use fugue::bytes::{ByteCast, Endian, Order, BE, LE};
pub use fugue::ir::convention::{Convention, Prototype, PrototypeEntry, PrototypeOperand, *};
pub use fugue::ir::language::{Language, LanguageBuilder, LanguageDB};
pub use fugue::ir::{AddressSpace, AddressSpaceId, SpaceManager, Translator};
pub use petgraph as graph;
pub use petgraph::graph::NodeIndex;
pub use petgraph::visit::EdgeRef;
pub use petgraph::Direction;

pub use crate::analyses::folded_xrefs::{FoldedXRefDB, FOLDED_XREF_ANALYSIS};
pub use crate::analyses::symbolic::typed::{
    AliasType, AliasTypingContext, AliasValue, AliasVisitor, ContextualTypeResolver,
    DefaultTypeResolver, ITypeResolver, InterContextualTypeResolver, IntraContextualTypeResolver,
    ResolvedType, TypedAliasValue, TypedAliases, TypedBlockAliases, TypedFunctionAliases,
    DEFAULT_TYPE_RESOLVER,
};
pub use crate::analyses::xrefs::{XRefDB, XREF_ANALYSIS};
pub use crate::arch::{AddressSet, Arch};
pub use crate::cfg::cg::{CallGraph, CallGraphEdge, CallGraphNode};
pub use crate::cfg::context::ICFGExtendedContext;
pub use crate::cfg::flow::{FlowInfo, FlowKind};
pub use crate::cfg::insn::{InsnInfo, InsnInfoId, InsnTerm, InsnTermTable};
pub use crate::cfg::ICFG;
pub use crate::cio::{TypeDB, TypeInfoDB};
pub use crate::data::strings::StringData;
pub use crate::data::DataTypeDB;
pub use crate::inject::{InjectionManager, InjectionOperand, InjectionStub};
pub use crate::ir::insn::{InsnChunk, InsnChunks, InsnOperand, InsnToken, IntraInsnCFG};
pub use crate::ir::term::{Term, TermMut};
pub use crate::ir::traits::BitSize;
pub use crate::ir::{
    Address, BinOp, BinRel, BitVec, BranchTarget, EnumVariant, Expr, FloatKind, FunctionArg,
    FunctionArgProps, Insn, InsnTarget, Location, SimpleVar, Stmt, StructField, ToAddress,
    TranslatorDisplay, Type, TypeKind, UnOp, UnRel, UnionVariant, Var, VarView, Variable,
};
pub use crate::kb::block::{CodeBlock, CodeBlockId, CodeBlockTable};
pub use crate::kb::function::{
    Function, FunctionCFG, FunctionDFG, FunctionDominance, FunctionId, FunctionSCCs, FunctionTable,
};
pub use crate::kb::function_summary::{
    FunctionRef, FunctionSummary, FunctionSummaryId, FunctionSummaryTable,
};
pub use crate::kb::id::Identifiable;
pub use crate::kb::offset_map::{OffsetLike, OffsetMap, OffsetValue, OffsetValueWith};
pub use crate::kb::operand::{Operand, OperandBuilder};
pub use crate::kb::phi::Phi;
pub use crate::kb::symbol::{Symbol, SymbolRef};
pub use crate::kb::xref::{XRef, XRefKind};
pub use crate::kb::{ustr, uuid, AHashMap, AHashSet, AHasher, Ustr, Uuid};
pub use crate::lifter::{
    DefaultPrototype, Disassembler, Lifter, LifterBuilder, LifterBuilderError, LifterError,
    PrototypeResolver,
};
pub use crate::loader::efi::{EFIModule, EFIModuleInfo, LoadedEFI, LoadedEFIModule};
pub use crate::loader::elf::LoadedELF;
pub use crate::loader::pe::LoadedPE;
pub use crate::loader::te::LoadedTE;
pub use crate::loader::{
    EFIFirmwareLoader, EFILoader, ELFLoader, LoadedBinary, Loader, LoaderAttribute, LoaderBlock,
    LoaderBytes, LoaderContainer, LoaderExport, LoaderFunction, LoaderImport, LoaderRegion,
    PELoader, TELoader,
};
pub use crate::project::analysis::{
    Analysis, AnalysisContext, AnalysisError, AnalysisInfo, AnalysisManager, AnalysisSchedule,
    AnalysisVersion, AnalysisVersionReq, Schedule,
};
pub use crate::project::io::{AnalysisStore, ProjectData};
pub use crate::project::{ICFGConfig, Project, ProjectConfig, ProjectContext, ProjectContextMut};
pub use crate::region::{Memory, Region, RegionIOError};
pub use crate::symbols::{SymbolTable, Symbolise, SymboliseError};

pub mod eval {
    pub mod state {
        pub use fuguex_state::{flat, paged, register, traits};
    }
}

pub mod efi {
    pub use crate::efi::aliases::{
        EFITypeResolver, EFITypedAliases, EFITypedAliasesConfig, IEFITypeResolver,
    };
    pub use crate::efi::globals::{GlobalsAnalyser, EFI_GLOBALS_ANALYSIS};
    pub use crate::efi::guids::{GuidAnalyser, GuidDB, GuidSignature, EFI_GUID_XREF_ANALYSIS};
    pub use crate::efi::image::depex;
    pub use crate::efi::meta::*;
    pub use crate::efi::module::{ModuleInfo, EFI_MODULE_INFO_ANALYSIS};
    pub use crate::efi::pei::*;
    pub use crate::efi::services::{ServicesAnalyser, EFI_SERVICES_ANALYSIS};
    pub use crate::efi::smi::{SmiHandlerAnalyser, EFI_SMI_HANDLER_ANALYSIS};
    pub use crate::efi::{image, EFIModuleType};
}

pub mod posix {
    pub use crate::posix::non_returning::{
        PosixNonReturningExternals, POSIX_NON_RETURNING_EXTERNALS,
    };
}

pub mod visit {
    pub use crate::ir::{Visit, VisitMut, VisitVars, VisitVarsMut};
}

pub mod windows {
    pub use crate::windows::non_returning::{
        WindowsNonReturningExternals, WINDOWS_NON_RETURNING_EXTERNALS,
    };
}
