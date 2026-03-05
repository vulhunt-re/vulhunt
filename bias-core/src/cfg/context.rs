use std::collections::BTreeSet;

use ahash::AHashMap;
use fugue::ir::Address;
use petgraph::graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use super::block::BlockInfo;
use super::insn::InsnInfoTable;
use super::specs::FunctionSpecManager;
use crate::cfg::{FlowKind, ICFG};
use crate::cio::TypeDB;
use crate::data::DataTypeDB;
use crate::eval::{Configuration as EvalConfiguration, EvalError, IREvaluator};
use crate::inject::InjectionManager;
use crate::kb::block::{CodeBlockId, CodeBlockTable};
use crate::kb::function::FunctionTable;
use crate::kb::function_summary::FunctionSummaryTable;
use crate::kb::table::MPointTable;
use crate::lifter::Lifter;
use crate::project::analysis::AnalysisManager;
use crate::project::ProjectContext;
use crate::region::Memory;
use crate::symbols::SymbolTable;

pub struct ICFGProjectContext<'a, 'b, 'c> {
    pub lifter: &'a Lifter,
    pub icfg: &'c mut ICFG,
    pub datadb: &'a DataTypeDB,
    pub itable: &'b InsnInfoTable,
    pub cbtable: &'a CodeBlockTable,
    pub ftable: &'a FunctionTable,
    pub fstable: &'a FunctionSummaryTable,
    pub symtab: &'a SymbolTable,
    pub memory: &'a Memory,
    pub typedb: &'a TypeDB,
    pub analyses: &'a AnalysisManager,
    pub injections: &'a InjectionManager,
}

impl<'a, 'b, 'c> ICFGProjectContext<'a, 'b, 'c> {
    pub fn evaluator(&self, config: EvalConfiguration) -> Result<IREvaluator, EvalError> {
        IREvaluator::new_with(self.tables(), config)
    }

    pub fn tables(&self) -> ProjectContext<'_, InsnInfoTable> {
        ProjectContext {
            lifter: self.lifter,
            icfg: &*self.icfg,
            datadb: &*self.datadb,
            itable: &*self.itable,
            cbtable: &*self.cbtable,
            ftable: &*self.ftable,
            fstable: &*self.fstable,
            symtab: &*self.symtab,
            memory: &*self.memory,
            typedb: &*self.typedb,
            analyses: &*self.analyses,
            injections: &*self.injections,
        }
    }
}

pub struct ICFGExtendedContext<'a, 'b, 'c, 'd, 'e> {
    pub lifter: &'a Lifter,
    pub icfg: &'c mut ICFG,
    pub datadb: &'a DataTypeDB,
    pub itable: &'b InsnInfoTable,
    pub cbtable: &'a CodeBlockTable,
    pub ftable: &'a FunctionTable,
    pub fstable: &'a FunctionSummaryTable,
    pub symtab: &'a SymbolTable,
    pub memory: &'a Memory,
    pub typedb: &'a TypeDB,
    pub analyses: &'a AnalysisManager,
    pub injections: &'a InjectionManager,
    pub specifications: &'a FunctionSpecManager<'a>,
    pub block_table: &'d mut MPointTable<Address, BlockInfo<'b>>,
    pub block_map: &'e mut AHashMap<Address, (NodeIndex, CodeBlockId)>,
    pub non_returning_functions: &'c mut BTreeSet<Address>,
    pub tail_functions: &'c mut BTreeSet<Address>,
}

impl<'a, 'b, 'c, 'd, 'e> ICFGExtendedContext<'a, 'b, 'c, 'd, 'e> {
    pub fn evaluator(&self, config: EvalConfiguration) -> Result<IREvaluator, EvalError> {
        IREvaluator::new_with(self.tables(), config)
    }

    pub fn tables(&self) -> ProjectContext<'_, InsnInfoTable> {
        ProjectContext {
            lifter: self.lifter,
            icfg: &*self.icfg,
            datadb: &*self.datadb,
            itable: &*self.itable,
            cbtable: &*self.cbtable,
            ftable: &*self.ftable,
            fstable: &*self.fstable,
            symtab: &*self.symtab,
            memory: &*self.memory,
            typedb: &*self.typedb,
            analyses: &*self.analyses,
            injections: &*self.injections,
        }
    }

    /// greedily returns a caller for the argument address.
    /// used, e.g., for GOT entries where exactly one caller exists
    pub fn get_caller_for(&self, addr: &Address) -> Option<Address> {
        let blk = self.block_table.get_point(addr)?;

        self.icfg
            .edges_directed(blk.node(), Direction::Incoming)
            .find_map(|e| {
                if e.weight().is_call() {
                    let src_block_id = self.icfg[e.source()];
                    let src_block = &self.block_table[src_block_id];
                    Some(src_block.start())
                } else {
                    None
                }
            })
    }

    pub fn mark_non_returning_flows(&mut self, addr: Address) {
        let Some(block) = self.block_table.get_point(addr) else {
            return;
        };

        // mark every incoming call edge as tailcall to signal that we are not returning
        let mut override_flows_for = Vec::<(NodeIndex, NodeIndex)>::new();
        for edge in self
            .icfg
            .edges_directed(block.node(), Direction::Incoming)
            .filter(|edge| edge.weight().is_call())
        {
            override_flows_for.push((edge.source(), edge.target()));
        }

        let mut fall_edges = Vec::<EdgeIndex>::new();
        for (src_node, tgt_node) in override_flows_for {
            self.icfg
                .update_edge(src_node, tgt_node, FlowKind::TailCallBranch);

            if let Some(edge) = self
                .icfg
                .edges_directed(src_node, Direction::Outgoing)
                .find(|edge| edge.weight().is_fall())
            {
                fall_edges.push(edge.id());
            }
        }

        // remove fall edge for caller block
        for fe in fall_edges {
            self.icfg.remove_edge(fe);
        }
    }
}
