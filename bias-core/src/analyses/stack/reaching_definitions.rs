use std::collections::hash_map::Entry;

use petgraph::visit::{EdgeRef, VisitMap, Visitable};
use petgraph::EdgeDirection;

use crate::analyses::stack::aliases::{
    FunctionStackAccesses, FunctionStackRefs, StackAccessVisitor, StackAccesses,
};
use crate::analyses::stack::StackVarDef;
use crate::prelude::visit::Visit;
use crate::prelude::*;

pub struct ReachingStackDefsVisitor<'a> {
    rsmapping: AHashMap<StackVarDef, Option<Location>>,
    call_rsmapping: Option<AHashMap<StackVarDef, Option<Location>>>,
    call_sp_shift: Option<i64>,
    sp: Var,
    location: Location,
    injections: &'a InjectionManager,
    registers: &'a VarView,
    clobbers: AHashSet<Var>,
    outputs: AHashSet<Var>,
    stack_accesses: &'a StackAccesses,
}

impl<'a> ReachingStackDefsVisitor<'a> {
    pub fn new(
        lifter: &'a Lifter,
        injections: &'a InjectionManager,
        stack_accesses: &'a StackAccesses,
    ) -> Self {
        Self::new_with(lifter, injections, AHashMap::default(), stack_accesses)
    }

    pub fn new_with(
        lifter: &'a Lifter,
        injections: &'a InjectionManager,
        rsmapping: AHashMap<StackVarDef, Option<Location>>,
        stack_accesses: &'a StackAccesses,
    ) -> Self {
        let prototype = lifter.default_prototype();
        let registers = &lifter.register_map();

        let clobbers = prototype
            .killed_registers()
            .into_iter()
            .map(|var| registers.parent(&var).unwrap_or(var))
            .collect();

        let outputs = prototype
            .output_registers()
            .into_iter()
            .map(|var| registers.parent(&var).unwrap_or(var))
            .collect();

        Self {
            rsmapping,
            call_rsmapping: None,
            call_sp_shift: None,
            sp: lifter.stack_pointer(),
            location: Location::default(),
            injections,
            registers,
            clobbers,
            outputs,
            stack_accesses,
        }
    }

    #[inline]
    fn eval_stmt(&mut self, stmt: &Term<Stmt>) {
        match &**stmt {
            Stmt::Assign(var, _expr) => {
                if var.is_address() || var.is_temporary() {
                    return;
                }

                let lvar = self.registers.parent(var).unwrap_or(*var);

                self.rsmapping.insert(lvar.into(), Some(self.location));
            }
            Stmt::Store(_, _, _sz, _) => {
                if let Some(stores) = self.stack_accesses.stores_at(&self.location) {
                    for store in stores {
                        self.rsmapping
                            .insert(StackVarDef::Stack(*store), Some(self.location));
                    }
                }
            }
            Stmt::Call(_, _) => {
                self.call_rsmapping = Some(self.rsmapping.clone());
                self.call_sp_shift = self
                    .stack_accesses
                    .call_state_at(&self.location)
                    .and_then(|cs| cs.get(&self.sp).copied());

                // NOTE: stack accesses will have processed the fixup;
                if let Some(f) = self
                    .stack_accesses
                    .call_fixup_at(&self.location)
                    .and_then(|f| {
                        self.injections
                            .get_function_stub(f)
                            .and_then(InjectionStub::fixup)
                    })
                {
                    for op in f.operations() {
                        self.eval_stmt(op);
                    }
                    return;
                }

                self.rsmapping.iter_mut().for_each(|(var, val)| {
                    if let StackVarDef::Var(var) = var {
                        if self.clobbers.contains(var) {
                            *val = None;
                        }
                    }
                });

                self.outputs.iter().for_each(|&var| {
                    self.rsmapping.insert(var.into(), Some(self.location));
                });
            }
            _ => (),
        }
    }

    #[inline]
    pub fn eval_insn(&mut self, insn: &Term<Insn>) {
        for (i, stmt) in insn.operations().iter().enumerate() {
            self.location = Location::new(insn.address(), i);
            self.eval_stmt(stmt);
        }
    }

    #[inline]
    pub fn eval_block(&mut self, block: &CodeBlock) {
        for insn in block.insns() {
            self.eval_insn(insn);
        }
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BlockReachingStackDefs {
    incoming: AHashMap<StackVarDef, Option<Location>>,
    outgoing: AHashMap<StackVarDef, Option<Location>>,
    call_state: Option<AHashMap<StackVarDef, Option<Location>>>,
    call_state_sp: Option<i64>,
}

impl BlockReachingStackDefs {
    pub fn incoming(&self) -> &AHashMap<StackVarDef, Option<Location>> {
        &self.incoming
    }

    pub fn incoming_defs(&self) -> impl Iterator<Item = (&StackVarDef, &Location)> {
        self.incoming.iter().filter_map(|(var, val)| {
            if let Some(val) = val.as_ref() {
                Some((var, val))
            } else {
                None
            }
        })
    }

    pub fn outgoing(&self) -> &AHashMap<StackVarDef, Option<Location>> {
        &self.outgoing
    }

    pub fn outgoing_defs(&self) -> impl Iterator<Item = (&StackVarDef, &Location)> {
        self.outgoing.iter().filter_map(|(var, val)| {
            if let Some(val) = val.as_ref() {
                Some((var, val))
            } else {
                None
            }
        })
    }

    pub fn call_state(&self) -> Option<&AHashMap<StackVarDef, Option<Location>>> {
        self.call_state.as_ref()
    }

    pub fn call_state_defs(&self) -> impl Iterator<Item = (&StackVarDef, &Location)> {
        self.call_state.iter().flatten().filter_map(|(var, val)| {
            if let Some(val) = val.as_ref() {
                Some((var, val))
            } else {
                None
            }
        })
    }

    #[inline]
    pub fn argument_provenance(
        &self,
        operand: &PrototypeOperand,
        lifter: &Lifter,
    ) -> Option<Location> {
        let call_state = self.call_state()?;

        match operand {
            PrototypeOperand::Register { varnode, .. } => {
                let var = Var::new0(
                    lifter.register_space(),
                    varnode.offset(),
                    varnode.size() as u32 * 8,
                );

                let avar = lifter.register_map().parent(&var).unwrap_or(var);

                call_state.get(&StackVarDef::new(avar)).copied()?
            }
            PrototypeOperand::StackRelative(offset) => {
                let stack = self.call_state_sp?;
                let stack_rel = StackVarDef::stack(stack + *offset as i64, lifter.address_bytes());
                call_state.get(&stack_rel).copied()?
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FunctionReachingStackDefs {
    blocks: AHashMap<CodeBlockId, BlockReachingStackDefs>,
}

impl FunctionReachingStackDefs {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn blocks(&self) -> &AHashMap<CodeBlockId, BlockReachingStackDefs> {
        &self.blocks
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReachingStackDefs {
    mapping: AHashMap<FunctionId, FunctionReachingStackDefs>,
}

impl ReachingStackDefs {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn mapping(&self) -> &AHashMap<FunctionId, FunctionReachingStackDefs> {
        &self.mapping
    }

    pub fn dfg(
        project: &Project,
        f: &Function,
        accesses: &FunctionStackRefs,
    ) -> FunctionDFG<StackVarDef> {
        struct Visitor<'a> {
            g: &'a mut FunctionDFG<StackVarDef>,
            loc: Location,
            vars: &'a VarView,
            mapping: &'a mut AHashMap<StackVarDef, Location>,
            accesses: &'a StackAccesses,
        }

        impl<'a, 'ir> Visit<'ir> for Visitor<'a> {
            fn visit_stmt_assign(&mut self, var: &'ir Var, _expr: &'ir Term<Expr>) {
                if var.is_address() {
                    return;
                }

                let nvar = self.vars.parent(var).unwrap_or(*var);

                self.mapping.insert(StackVarDef::Var(nvar), self.loc);
            }

            fn visit_stmt_store(
                &mut self,
                _target: &'ir Term<Expr>,
                _source: &'ir Term<Expr>,
                _bits: u32,
                _space: AddressSpaceId,
            ) {
                if let Some(stores) = self.accesses.stores_at(&self.loc) {
                    for store in stores.iter() {
                        self.mapping
                            .insert(StackVarDef::Stack(store.to_owned()), self.loc);
                    }
                }
            }

            fn visit_expr_load(
                &mut self,
                _source: &'ir Term<Expr>,
                _bits: u32,
                _space: AddressSpaceId,
            ) {
                if let Some(loads) = self.accesses.loads_at(&self.loc) {
                    let sloc = self.loc;
                    for load in loads.iter() {
                        let uvar = StackVarDef::Stack(*load);

                        if let Some(&dloc) = self.mapping.get(&uvar) {
                            if dloc != sloc {
                                self.g.add_dependency(dloc, sloc, uvar);
                            }
                        }
                    }
                }
            }

            fn visit_expr_var(&mut self, var: &'ir Var) {
                if var.is_address() || var.is_temporary() {
                    return;
                }

                let nvar = self.vars.parent(var).unwrap_or(*var);
                let uvar = StackVarDef::Var(nvar);
                let sloc = self.loc;

                if let Some(&dloc) = self.mapping.get(&uvar) {
                    if dloc != sloc {
                        self.g.add_dependency(dloc, sloc, uvar);
                    }
                }
            }

            fn visit_hint_pointer(&mut self, _expr: &'ir Var) {}
        }

        let mut g = FunctionDFG::new();
        let mut visitor =
            StackAccessVisitor::new(project.lifter(), project.functions(), project.injections());
        let frdefs = Self::analyse_function(project, f, accesses);

        let mut bmapping = AHashMap::new();

        for block in f.blocks_with(project.code_blocks()) {
            let bid = block.id();

            let refs = &accesses.blocks()[&bid];
            let rdefs = &frdefs.blocks()[&bid];

            let block_accesses = visitor.analyse_block(refs, block);

            bmapping.extend(
                rdefs
                    .incoming()
                    .iter()
                    .filter_map(|(v, l)| l.map(|l| (v.to_owned(), l))),
            );

            for insn in block.insns() {
                for (i, op) in insn.operations().iter().enumerate() {
                    Visitor {
                        g: &mut g,
                        loc: Location::new(insn.address(), i),
                        mapping: &mut bmapping,
                        accesses: &block_accesses,
                        vars: &*project.lifter().register_map(),
                    }
                    .visit_stmt(op);
                }
            }

            bmapping.clear();
        }

        g
    }

    #[inline]
    pub fn analyse_function(
        project: &Project,
        f: &Function,
        accesses: &FunctionStackRefs,
    ) -> FunctionReachingStackDefs {
        Self::analyse_function_with(project, f, accesses, None)
    }

    #[inline]
    pub fn analyse_function_with<'a>(
        project: &'a Project,
        f: &'a Function,
        accesses: &'a FunctionStackRefs,
        block_accesses: impl Into<Option<&'a FunctionStackAccesses>>,
    ) -> FunctionReachingStackDefs {
        let mut gkmap = AHashMap::new();

        let lifter = project.lifter();
        let mut blk_accesses = AHashMap::with_capacity(0);

        let block_accesses = match block_accesses.into() {
            Some(accesses) => {
                for blk in f.blocks_with(project.code_blocks()) {
                    let id = blk.id();
                    gkmap.insert(id, BlockReachingStackDefs::default());
                }
                accesses.blocks()
            }
            None => {
                let mut access_visitor =
                    StackAccessVisitor::new(lifter, project.functions(), project.injections());

                for blk in f.blocks_with(project.code_blocks()) {
                    let id = blk.id();
                    gkmap.insert(id, BlockReachingStackDefs::default());
                    blk_accesses.insert(
                        id,
                        access_visitor.analyse_block(&accesses.blocks()[&id], blk),
                    );
                }

                &blk_accesses
            }
        };

        let (cfg, mut worklist) = f.rev_post_ordered_visitor(project.icfg(), project.code_blocks());
        let mut edge_visitor = cfg.visit_map();

        while let Some(blk) =
            worklist.next_with(&cfg, |cfg, nx| Some(&project.code_blocks()[cfg[nx]]))
        {
            let mut nincoming = AHashMap::new();

            edge_visitor.clear();

            for pred in project
                .icfg()
                .edges_directed(blk.node(), EdgeDirection::Incoming)
                .filter_map(|e| {
                    if edge_visitor.visit(e.source()) {
                        gkmap.get(&project.icfg()[e.source()])
                    } else {
                        None
                    }
                })
            {
                for (k, v) in pred.outgoing.iter() {
                    match nincoming.entry(*k) {
                        Entry::Occupied(mut e) => {
                            if v != e.get() {
                                e.insert(None);
                            }
                        }
                        Entry::Vacant(e) => {
                            e.insert(v.to_owned());
                        }
                    }
                }
            }

            let accesses = &block_accesses[&blk.id()];

            let mut builder = ReachingStackDefsVisitor::new_with(
                lifter,
                project.injections(),
                nincoming.clone(),
                accesses,
            );

            builder.eval_block(blk);

            let noutgoing = builder.rsmapping;

            let current = gkmap.get_mut(&blk.id()).unwrap();
            let did_change = noutgoing != current.outgoing;

            current.incoming = nincoming;
            current.outgoing = noutgoing;
            current.call_state_sp = builder.call_sp_shift;
            current.call_state = builder.call_rsmapping;

            if did_change {
                worklist.push_unique_neighbors(&cfg, blk.node(), EdgeDirection::Outgoing);
            }
        }

        FunctionReachingStackDefs { blocks: gkmap }
    }
}
