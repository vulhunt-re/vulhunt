use std::collections::hash_map::Entry;
use std::fmt::Display;

use petgraph::visit::{EdgeRef, IntoEdgesDirected, VisitMap, Visitable};
use petgraph::EdgeDirection;

use crate::analyses::stack::aliases::{
    FunctionStackAccesses, FunctionStackRefs, StackAccessVisitor, StackAccesses,
};
use crate::analyses::stack::StackVarDef;
use crate::kb::block::CodeBlockTable;
use crate::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash, serde::Serialize, serde::Deserialize)]
pub enum UninitValue {
    Top,
    Val { loc: Location, def: StackVarDef },
    Bot,
}

impl Default for UninitValue {
    fn default() -> Self {
        Self::Bot
    }
}

impl Display for UninitValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Top => write!(f, "T"),
            Self::Bot => write!(f, "?"),
            Self::Val { loc, def } => write!(f, "uninit. from {loc} (via {def})"),
        }
    }
}

impl UninitValue {
    pub fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }

    pub fn is_bot(&self) -> bool {
        matches!(self, Self::Bot)
    }

    pub fn is_unk(&self) -> bool {
        matches!(self, Self::Top | Self::Bot)
    }

    pub fn val(loc: impl Into<Location>, def: impl Into<StackVarDef>) -> Self {
        Self::Val {
            loc: loc.into(),
            def: def.into(),
        }
    }

    pub fn as_val(&self) -> Option<(&Location, &StackVarDef)> {
        if let Self::Val { loc, def } = self {
            Some((loc, def))
        } else {
            None
        }
    }

    pub fn join(&mut self, other: Self) {
        match (&self, other) {
            (Self::Top, _) | (_, Self::Top) => {
                *self = Self::Top;
            }
            (Self::Bot, v) => {
                *self = v;
            }
            (_, Self::Bot) => {}
            (Self::Val { loc: l1, def: d1 }, Self::Val { loc: l2, def: d2 }) => {
                if *d1 != d2 {
                    *self = Self::Top;
                } else if *l1 != l2 {
                    // We have the fact that d1 and d2 are the same (let's say uninit reg1),
                    // but the assignments happened at different points, so we pick one
                    // consistently.
                    //
                    *self = Self::Val {
                        loc: (*l1).max(l2),
                        def: d2,
                    };
                }
            }
        }
    }
}

pub struct ReachingUninitValuesVisitor<'a> {
    rsmapping: AHashMap<StackVarDef, UninitValue>,
    tmapping: AHashMap<Var, UninitValue>,
    location: Location,
    injections: &'a InjectionManager,
    registers: &'a VarView,
    clobbers: AHashSet<Var>,
    stack_accesses: &'a StackAccesses,
}

impl<'a> ReachingUninitValuesVisitor<'a> {
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
        rsmapping: AHashMap<StackVarDef, UninitValue>,
        stack_accesses: &'a StackAccesses,
    ) -> Self {
        let prototype = lifter.default_prototype();
        let registers = &lifter.register_map();
        let clobbers = prototype
            .killed_registers()
            .into_iter()
            .chain(prototype.output_registers().into_iter())
            .map(|var| registers.parent(&var).unwrap_or(var))
            .collect();

        Self {
            rsmapping,
            tmapping: AHashMap::default(),
            location: Location::default(),
            injections,
            registers,
            clobbers,
            stack_accesses,
        }
    }

    #[inline]
    fn eval_expr(&mut self, expr: &Term<Expr>) -> UninitValue {
        match &**expr {
            Expr::Var(rvar) => {
                let rvar = self.registers.parent(rvar).unwrap_or(*rvar);
                let prov = UninitValue::Val {
                    loc: self.location,
                    def: rvar.into(),
                };

                if rvar.is_register() {
                    self.rsmapping
                        .get(&StackVarDef::Var(rvar))
                        .cloned()
                        .unwrap_or(prov)
                } else if rvar.is_temporary() {
                    self.tmapping.get(&rvar).cloned().unwrap_or(prov)
                } else {
                    prov
                }
            }
            Expr::Val(_, _) => UninitValue::Top,
            Expr::UnOp(_, expr) => {
                let val = self.eval_expr(expr);
                if val.is_bot() {
                    UninitValue::Bot
                } else {
                    UninitValue::Top
                }
            }
            Expr::BinOp(_, lexpr, rexpr) => {
                let mut lval = self.eval_expr(lexpr);
                let rval = self.eval_expr(rexpr);
                lval.join(rval);
                lval
            }
            Expr::Load(expr, _, _) => {
                let aval = self.eval_expr(expr);

                if let Some(loads) = self.stack_accesses.loads_at(&self.location) {
                    for load in loads {
                        if let Some(val) = self.rsmapping.get(&StackVarDef::Stack(*load)) {
                            return val.clone();
                        }
                    }

                    return UninitValue::Top;
                }

                if aval.is_bot() {
                    UninitValue::Bot
                } else {
                    UninitValue::Top
                }
            }
            _ => UninitValue::Top,
        }
    }

    #[inline]
    fn eval_stmt(&mut self, stmt: &Term<Stmt>) {
        match &**stmt {
            Stmt::Assign(var, expr) => {
                if var.is_address() {
                    self.eval_expr(expr);
                    return;
                }

                let lvar = self.registers.parent(var).unwrap_or(*var);
                let val = self.eval_expr(expr);

                if lvar.is_register() {
                    self.rsmapping.insert(lvar.into(), val);
                } else {
                    self.tmapping.insert(lvar, val);
                }
            }
            Stmt::Store(_, src, _, _) => {
                let val = self.eval_expr(src);
                if let Some(stores) = self.stack_accesses.stores_at(&self.location) {
                    for store in stores {
                        self.rsmapping
                            .insert(StackVarDef::Stack(*store), val.clone());
                    }
                }
            }
            Stmt::Call(_, _) => {
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
                            //*val = UninitValue::Top;
                            *val = UninitValue::Bot;
                        }
                    }
                });
            }
            _ => (),
        }
    }

    #[inline]
    pub fn eval_insn(&mut self, insn: &Term<Insn>) {
        self.tmapping.clear();
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
pub struct BlockReachingUninitValues {
    incoming: AHashMap<StackVarDef, UninitValue>,
    outgoing: AHashMap<StackVarDef, UninitValue>,
}

impl BlockReachingUninitValues {
    pub fn incoming(&self) -> &AHashMap<StackVarDef, UninitValue> {
        &self.incoming
    }

    pub fn incoming_values(&self) -> impl Iterator<Item = (&StackVarDef, &Location, &StackVarDef)> {
        self.incoming.iter().filter_map(|(var, val)| {
            if let Some((loc, def)) = val.as_val() {
                Some((var, loc, def))
            } else {
                None
            }
        })
    }

    pub fn outgoing(&self) -> &AHashMap<StackVarDef, UninitValue> {
        &self.outgoing
    }

    pub fn outgoing_values(&self) -> impl Iterator<Item = (&StackVarDef, &Location, &StackVarDef)> {
        self.outgoing.iter().filter_map(|(var, val)| {
            if let Some((loc, def)) = val.as_val() {
                Some((var, loc, def))
            } else {
                None
            }
        })
    }

    pub fn widen(
        v1: &mut AHashMap<StackVarDef, UninitValue>,
        v2: &AHashMap<StackVarDef, UninitValue>,
    ) -> bool {
        let mut did_widen = false;

        for (k, other) in v2.iter() {
            if let Some(v) = v1.get_mut(&k) {
                match (&v, other) {
                    (
                        UninitValue::Val { loc: l1, def: d1 },
                        UninitValue::Val { loc: l2, def: d2 },
                    ) => {
                        if d1 != d2 {
                            did_widen = true;
                            *v = UninitValue::Top;
                        } else if l1 != l2 {
                            did_widen = true;
                            *v = UninitValue::Val {
                                loc: (*l1).max(*l2),
                                def: *d1,
                            };
                        }
                    }
                    (UninitValue::Val { .. }, UninitValue::Top) => {
                        did_widen = true;
                        *v = UninitValue::Top;
                    }
                    (UninitValue::Bot, v2) if !v2.is_bot() => {
                        did_widen = true;
                        *v = UninitValue::Top;
                    }
                    _ => (),
                }
            } else {
                v1.insert(*k, UninitValue::Top);
                did_widen = true;
            }
        }

        did_widen
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FunctionReachingUninitValues {
    blocks: AHashMap<CodeBlockId, BlockReachingUninitValues>,
}

impl FunctionReachingUninitValues {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn blocks(&self) -> &AHashMap<CodeBlockId, BlockReachingUninitValues> {
        &self.blocks
    }

    #[inline]
    pub fn definitely_killed(&self, cbtable: &CodeBlockTable) -> AHashSet<StackVarDef> {
        self.definitely_killed_with(cbtable, false)
    }

    #[inline]
    pub fn definitely_killed_with(
        &self,
        cbtable: &CodeBlockTable,
        stack: bool,
    ) -> AHashSet<StackVarDef> {
        let it = self.blocks.iter().filter_map(|(blk, uninits)| {
            if cbtable[*blk].is_return() {
                Some(uninits)
            } else {
                None
            }
        });

        let mut vs = AHashSet::new();

        for retn in it {
            vs.extend(retn.outgoing().iter().filter_map(|(var, val)| {
                if !stack && var.is_stack() {
                    return None;
                }

                match val {
                    UninitValue::Top | UninitValue::Bot => Some(*var),
                    UninitValue::Val { def, .. } if def != var => Some(*var),
                    _ => None,
                }
            }));
        }

        vs
    }

    #[inline]
    pub fn preserved_or_restored(&self, cbtable: &CodeBlockTable) -> AHashSet<StackVarDef> {
        self.preserved_or_restored_with(cbtable, false)
    }

    #[inline]
    pub fn preserved_or_restored_with(
        &self,
        cbtable: &CodeBlockTable,
        stack: bool,
    ) -> AHashSet<StackVarDef> {
        let mut it = self.blocks.iter().filter_map(|(blk, uninits)| {
            if cbtable[*blk].is_return() {
                Some(uninits)
            } else {
                None
            }
        });

        let mut init = if let Some(vars) = it.next() {
            if stack {
                vars.outgoing_values()
                    .filter_map(|(var, _, def)| if var == def { Some(var.clone()) } else { None })
                    .collect::<AHashSet<_>>()
            } else {
                vars.outgoing_values()
                    .filter_map(|(var, _, def)| {
                        if !var.is_stack() && var == def {
                            Some(var.to_owned())
                        } else {
                            None
                        }
                    })
                    .collect()
            }
        } else {
            return AHashSet::with_capacity(0);
        };

        for rest in it {
            init.retain(|k| matches!(rest.outgoing().get(k), Some(v) if !v.is_unk()));
        }

        init
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReachingUninitValues {
    mapping: AHashMap<FunctionId, FunctionReachingUninitValues>,
}

impl ReachingUninitValues {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn mapping(&self) -> &AHashMap<FunctionId, FunctionReachingUninitValues> {
        &self.mapping
    }

    #[inline]
    pub fn analyse_function(
        project: &Project,
        f: &Function,
        accesses: &FunctionStackRefs,
    ) -> FunctionReachingUninitValues {
        Self::analyse_function_with(project, f, accesses, None)
    }

    #[inline]
    pub fn analyse_function_with<'a>(
        project: &'a Project,
        f: &'a Function,
        accesses: &'a FunctionStackRefs,
        block_accesses: impl Into<Option<&'a FunctionStackAccesses>>,
    ) -> FunctionReachingUninitValues {
        let mut gkmap = AHashMap::new();

        let lifter = project.lifter();
        let functions = project.functions();
        let injections = project.injections();

        let mut blk_accesses = AHashMap::with_capacity(0);

        let block_accesses = match block_accesses.into() {
            Some(accesses) => {
                for blk in f.blocks_with(project.code_blocks()) {
                    let id = blk.id();
                    gkmap.insert(id, BlockReachingUninitValues::default());
                }
                accesses.blocks()
            }
            None => {
                let mut access_visitor = StackAccessVisitor::new(lifter, functions, injections);

                for blk in f.blocks_with(project.code_blocks()) {
                    let id = blk.id();
                    gkmap.insert(id, BlockReachingUninitValues::default());
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
            let mut nincoming = AHashMap::<StackVarDef, UninitValue>::new();

            edge_visitor.clear();

            for pred in cfg
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
                            //println!("{} JOIN: {} with {}", k, e.get(), v);
                            e.get_mut().join(v.to_owned());
                        }
                        Entry::Vacant(e) => {
                            e.insert(v.to_owned());
                        }
                    }
                }
            }

            let accesses = &block_accesses[&blk.id()];

            let mut builder = ReachingUninitValuesVisitor::new_with(
                lifter,
                injections,
                nincoming.clone(),
                accesses,
            );

            builder.eval_block(blk);

            let mut noutgoing = builder.rsmapping;

            let current = gkmap.get_mut(&blk.id()).unwrap();
            let mut did_change = noutgoing != current.outgoing;

            if did_change {
                /*
                println!("--- incoming @ {} ---", blk.address());

                for (k, v) in current.incoming.iter() {
                    if let Some(other) = nincoming.get(&k) {
                        if other != v {
                            println!("{k}: {v} vs {other}");
                        }
                    } else {
                        println!("{k}: <new>");
                    }
                }

                println!("--- outgoing @ {} ---", blk.address());
                for (k, v) in current.outgoing.iter() {
                    if let Some(other) = noutgoing.get(&k) {
                        if other != v {
                            println!("{k}: {v} vs {other}");
                        }
                    } else {
                        println!("{k}: <new>");
                    }
                }

                println!("--- incoming vs outgoing @ {} ---", blk.address());
                for (k, v) in noutgoing.iter() {
                    if let Some(other) = nincoming.get(&k) {
                        if other != v {
                            println!("{k}: {v} vs {other}");
                        }
                    } else {
                        println!("{k}: <new>");
                    }
                }
                */

                // Widening to ensure monotone
                if BlockReachingUninitValues::widen(&mut noutgoing, &current.outgoing) {
                    did_change = noutgoing != current.outgoing;
                }
            }

            current.incoming = nincoming;
            current.outgoing = noutgoing;

            if did_change {
                worklist.push_unique_neighbors(&cfg, blk.node(), EdgeDirection::Outgoing);
            }
        }

        FunctionReachingUninitValues { blocks: gkmap }
    }
}
