use std::collections::hash_map::Entry;

use petgraph::visit::{EdgeRef, VisitMap, Visitable};
use petgraph::EdgeDirection;

use crate::analyses::stack::aliases::{
    FunctionStackAccesses, FunctionStackRefs, StackAccessVisitor, StackAccesses,
};
use crate::analyses::stack::StackVarDef;
use crate::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub struct AssignmentProv {
    location: Location,
    variable: StackVarDef,
}

impl AssignmentProv {
    pub fn new(location: impl Into<Location>, variable: impl Into<StackVarDef>) -> Self {
        Self {
            location: location.into(),
            variable: variable.into(),
        }
    }
}

pub struct ReachingStackProvVisitor<'a> {
    mapping: AHashMap<StackVarDef, Option<Location>>,
    prov_mapping: AHashMap<AssignmentProv, Option<AssignmentProv>>,
    location: Location,
    clobbers: AHashSet<Var>,
    outputs: AHashSet<Var>,
    injections: &'a InjectionManager,
    registers: &'a VarView,
    stack_accesses: &'a StackAccesses,
}

impl<'a> ReachingStackProvVisitor<'a> {
    pub fn new(
        lifter: &'a Lifter,
        injections: &'a InjectionManager,
        stack_accesses: &'a StackAccesses,
    ) -> Self {
        Self::new_with(
            lifter,
            injections,
            AHashMap::default(),
            AHashMap::default(),
            stack_accesses,
        )
    }

    pub fn new_with(
        lifter: &'a Lifter,
        injections: &'a InjectionManager,
        mapping: AHashMap<StackVarDef, Option<Location>>,
        prov_mapping: AHashMap<AssignmentProv, Option<AssignmentProv>>,
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
            mapping,
            prov_mapping,
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
            Stmt::Assign(var, expr) => {
                if var.is_address() {
                    return;
                }

                let lvar = self.registers.parent(var).unwrap_or(*var);

                match &**expr {
                    Expr::Var(var) if !var.is_address() => {
                        let rvar = StackVarDef::new(self.registers.parent(var).unwrap_or(*var));
                        let rloc = self.mapping.get(&rvar).and_then(|r| r.as_ref());
                        let prov = rloc
                            .and_then(|&loc| {
                                self.prov_mapping
                                    .get(&AssignmentProv::new(loc, rvar))
                                    .cloned()
                            })
                            .and_then(|v| v);

                        let lvar = StackVarDef::new(lvar);
                        let lprov = AssignmentProv::new(self.location, lvar);

                        self.prov_mapping.insert(lprov, prov);
                        if let Some(rloc) = rloc {
                            self.mapping.insert(lvar, Some(*rloc));
                        } else {
                            self.mapping.insert(lvar, Some(self.location));
                        }
                        return;
                    }
                    Expr::Load(_, _sz, _) => {
                        if let Some(loads) = self.stack_accesses.loads_at(&self.location) {
                            for &load in loads {
                                let rvar = StackVarDef::new(load);
                                let rloc = self.mapping.get(&rvar).and_then(|r| r.as_ref());
                                let prov = rloc
                                    .and_then(|&loc| {
                                        self.prov_mapping
                                            .get(&AssignmentProv::new(loc, rvar))
                                            .cloned()
                                    })
                                    .and_then(|v| v);

                                let lvar = StackVarDef::new(lvar);
                                let lprov = AssignmentProv::new(self.location, lvar);

                                self.prov_mapping.insert(lprov, prov);
                                if let Some(rloc) = rloc {
                                    self.mapping.insert(lvar, Some(*rloc));
                                } else {
                                    self.mapping.insert(lvar, Some(self.location));
                                }
                            }
                            return;
                        }
                    }
                    _ => (),
                }

                let lvar = StackVarDef::new(lvar);
                let lprov = AssignmentProv::new(self.location, lvar);

                self.mapping.insert(lvar, Some(self.location));
                self.prov_mapping.insert(lprov, Some(lprov));
            }
            Stmt::Store(_, expr, _sz, _) => {
                if let Some(stores) = self.stack_accesses.stores_at(&self.location) {
                    match &**expr {
                        Expr::Var(var) if !var.is_address() => {
                            let rvar = StackVarDef::new(self.registers.parent(var).unwrap_or(*var));
                            let rloc = self.mapping.get(&rvar).and_then(|r| r.as_ref()).copied();
                            let prov = rloc
                                .and_then(|loc| {
                                    self.prov_mapping
                                        .get(&AssignmentProv::new(loc, rvar))
                                        .cloned()
                                })
                                .and_then(|v| v);

                            for &store in stores {
                                let lvar = StackVarDef::new(store);
                                let lprov = AssignmentProv::new(self.location, lvar);

                                self.prov_mapping.insert(lprov, prov);
                                if let Some(rloc) = rloc {
                                    self.mapping.insert(lvar, Some(rloc));
                                } else {
                                    self.mapping.insert(lvar, Some(self.location));
                                }
                            }
                        }
                        Expr::Load(_, _sz, _) => {
                            if let Some(loads) = self.stack_accesses.loads_at(&self.location) {
                                for &load in loads {
                                    let rvar = StackVarDef::new(load);
                                    let rloc =
                                        self.mapping.get(&rvar).and_then(|r| r.as_ref()).copied();
                                    let prov = rloc
                                        .and_then(|loc| {
                                            self.prov_mapping
                                                .get(&AssignmentProv::new(loc, rvar))
                                                .cloned()
                                        })
                                        .and_then(|v| v);

                                    for &store in stores {
                                        let lvar = StackVarDef::new(store);
                                        let lprov = AssignmentProv::new(self.location, lvar);

                                        self.prov_mapping.insert(lprov, prov);
                                        if let Some(rloc) = rloc {
                                            self.mapping.insert(lvar, Some(rloc));
                                        } else {
                                            self.mapping.insert(lvar, Some(self.location));
                                        }
                                    }
                                }
                            }
                        }
                        _ => (),
                    }
                }
            }
            Stmt::Call(_, _) => {
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

                self.mapping.iter_mut().for_each(|(var, val)| {
                    if let StackVarDef::Var(var) = var {
                        if self.clobbers.contains(var) {
                            *val = None;

                            let prov = AssignmentProv::new(self.location, *var);
                            self.prov_mapping.insert(prov, Some(prov));
                        }
                    }
                });

                self.outputs.iter().for_each(|&var| {
                    self.mapping.insert(var.into(), Some(self.location));

                    let prov = AssignmentProv::new(self.location, var);
                    self.prov_mapping.insert(prov, Some(prov));
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
pub struct BlockReachingStackProv {
    incoming_mapping: AHashMap<StackVarDef, Option<Location>>,
    incoming_prov_mapping: AHashMap<AssignmentProv, Option<AssignmentProv>>,

    outgoing_mapping: AHashMap<StackVarDef, Option<Location>>,
    outgoing_prov_mapping: AHashMap<AssignmentProv, Option<AssignmentProv>>,
}

impl BlockReachingStackProv {
    pub fn incoming(&self) -> &AHashMap<StackVarDef, Option<Location>> {
        &self.incoming_mapping
    }

    pub fn incoming_defs(&self) -> impl Iterator<Item = (&StackVarDef, &Location)> {
        self.incoming_mapping.iter().filter_map(|(var, val)| {
            if matches!(var, StackVarDef::Var(v) if v.is_temporary()) {
                return None;
            }

            if let Some(val) = val.as_ref() {
                Some((var, val))
            } else {
                None
            }
        })
    }

    pub fn outgoing(&self) -> &AHashMap<StackVarDef, Option<Location>> {
        &self.outgoing_mapping
    }

    pub fn outgoing_defs(&self) -> impl Iterator<Item = (&StackVarDef, &Location)> {
        self.outgoing_mapping.iter().filter_map(|(var, val)| {
            if matches!(var, StackVarDef::Var(v) if v.is_temporary()) {
                return None;
            }

            if let Some(val) = val.as_ref() {
                Some((var, val))
            } else {
                None
            }
        })
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FunctionReachingStackProv {
    blocks: AHashMap<CodeBlockId, BlockReachingStackProv>,
}

impl FunctionReachingStackProv {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn blocks(&self) -> &AHashMap<CodeBlockId, BlockReachingStackProv> {
        &self.blocks
    }
}

pub struct ReachingStackProv;

impl ReachingStackProv {
    #[inline]
    pub fn analyse_function(
        project: &Project,
        f: &Function,
        accesses: &FunctionStackRefs,
    ) -> FunctionReachingStackProv {
        Self::analyse_function_with(project, f, accesses, None)
    }

    #[inline]
    pub fn analyse_function_with<'a>(
        project: &'a Project,
        f: &'a Function,
        accesses: &'a FunctionStackRefs,
        block_accesses: impl Into<Option<&'a FunctionStackAccesses>>,
    ) -> FunctionReachingStackProv {
        let mut gkmap = AHashMap::new();

        let lifter = project.lifter();
        let functions = project.functions();
        let injections = project.injections();

        let mut blk_accesses = AHashMap::with_capacity(0);

        let block_accesses = match block_accesses.into() {
            Some(accesses) => {
                for blk in f.blocks_with(project.code_blocks()) {
                    let id = blk.id();
                    gkmap.insert(id, BlockReachingStackProv::default());
                }
                accesses.blocks()
            }
            None => {
                let mut access_visitor = StackAccessVisitor::new(lifter, functions, injections);

                for blk in f.blocks_with(project.code_blocks()) {
                    let id = blk.id();
                    gkmap.insert(id, BlockReachingStackProv::default());
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
            let mut nincoming_mapping = AHashMap::new();
            let mut nincoming_prov_mapping = AHashMap::new();

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
                for (&k, v) in pred.outgoing_mapping.iter() {
                    match nincoming_mapping.entry(k) {
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

                for (&k, v) in pred.outgoing_prov_mapping.iter() {
                    match nincoming_prov_mapping.entry(k) {
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

            let mut builder = ReachingStackProvVisitor::new_with(
                lifter,
                injections,
                nincoming_mapping.clone(),
                nincoming_prov_mapping.clone(),
                accesses,
            );

            builder.eval_block(blk);

            let noutgoing_mapping = builder.mapping;
            let noutgoing_prov_mapping = builder.prov_mapping;

            let current = gkmap.get_mut(&blk.id()).unwrap();
            let did_change = noutgoing_mapping != current.outgoing_mapping
                || noutgoing_prov_mapping != current.outgoing_prov_mapping;

            current.incoming_mapping = nincoming_mapping;
            current.incoming_prov_mapping = nincoming_prov_mapping;

            current.outgoing_mapping = noutgoing_mapping;
            current.outgoing_prov_mapping = noutgoing_prov_mapping;

            if did_change {
                worklist.push_unique_neighbors(&cfg, blk.node(), EdgeDirection::Outgoing);
            }
        }

        FunctionReachingStackProv { blocks: gkmap }
    }
}
