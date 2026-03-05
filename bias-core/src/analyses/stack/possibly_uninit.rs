use std::borrow::Cow;

use indexmap::IndexSet;

use crate::analyses::stack::aliases::{
    FunctionStackAccesses, FunctionStackRefs, StackAccessVisitor, StackAccesses,
};
use crate::analyses::stack::reaching_definitions::FunctionReachingStackDefs;
use crate::analyses::stack::StackVarDef;
use crate::prelude::visit::Visit;
use crate::prelude::*;

pub struct UninitUsesVisitor<'a> {
    rsmapping: AHashMap<Location, AHashSet<StackVarDef>>,
    defined: Cow<'a, AHashMap<StackVarDef, Option<Location>>>,
    location: Location,
    registers: &'a VarView,
    clobbers: AHashSet<Var>,
    outputs: AHashSet<Var>,
    stack_accesses: &'a StackAccesses,
}

impl<'a, 'ir> Visit<'ir> for UninitUsesVisitor<'a> {
    fn visit_expr_var(&mut self, var: &'ir Var) {
        if var.is_address() || var.is_temporary() {
            return;
        }

        let lvar = StackVarDef::Var(self.registers.parent(var).unwrap_or(*var));
        if self.defined.contains_key(&lvar) {
            return;
        }

        self.rsmapping
            .entry(self.location)
            .or_default()
            .insert(lvar);
    }

    fn visit_expr_load(&mut self, _source: &'ir Term<Expr>, _bits: u32, _space: AddressSpaceId) {
        if let Some(loads) = self.stack_accesses.loads_at(&self.location) {
            loads.iter().for_each(|load| {
                let load = StackVarDef::Stack(*load);
                if !self.defined.contains_key(&load) {
                    self.rsmapping
                        .entry(self.location)
                        .or_default()
                        .insert(load);
                }
            });
        }
    }

    fn visit_hint_pointer(&mut self, _expr: &'ir Var) {}
}

impl<'a> UninitUsesVisitor<'a> {
    pub fn new(
        lifter: &'a Lifter,
        defined: &'a AHashMap<StackVarDef, Option<Location>>,
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
            rsmapping: AHashMap::default(),
            defined: Cow::Borrowed(defined),
            location: Location::default(),
            registers,
            clobbers,
            outputs,
            stack_accesses,
        }
    }

    #[inline]
    fn eval_stmt(&mut self, stmt: &Term<Stmt>) {
        // ensure we process uninit before making defs
        self.visit_stmt(stmt);

        match &**stmt {
            Stmt::Assign(var, _) => {
                if var.is_address() || var.is_temporary() {
                    return;
                }

                let lvar = self.registers.parent(var).unwrap_or(*var);

                self.defined
                    .to_mut()
                    .insert(lvar.into(), Some(self.location));
            }
            Stmt::Store(_, _, _sz, _) => {
                if let Some(stores) = self.stack_accesses.stores_at(&self.location) {
                    for store in stores {
                        self.defined
                            .to_mut()
                            .insert(StackVarDef::Stack(*store), Some(self.location));
                    }
                }
            }
            Stmt::Call(_, _) => {
                self.defined.to_mut().extend(
                    self.clobbers
                        .iter()
                        .chain(self.outputs.iter())
                        .copied()
                        .map(StackVarDef::Var)
                        .map(|v| (v, Some(self.location))),
                );
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
pub struct BlockUninitUses {
    uninit_uses: AHashMap<Location, AHashSet<StackVarDef>>,
}

impl BlockUninitUses {
    pub fn uninit_uses(&self) -> &AHashMap<Location, AHashSet<StackVarDef>> {
        &self.uninit_uses
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FunctionUninitUses {
    blocks: AHashMap<CodeBlockId, BlockUninitUses>,
}

impl FunctionUninitUses {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn blocks(&self) -> &AHashMap<CodeBlockId, BlockUninitUses> {
        &self.blocks
    }

    #[inline]
    pub fn possible_arguments(&self, lifter: &Lifter) -> Vec<StackVarDef> {
        self.possible_arguments_with(lifter, None)
    }

    #[inline]
    pub fn possible_arguments_with(
        &self,
        lifter: &Lifter,
        max_n: impl Into<Option<usize>>,
    ) -> Vec<StackVarDef> {
        let max_n = max_n.into().unwrap_or(10);
        let proto = lifter.default_prototype();

        let args = IndexSet::<StackVarDef, AHashRandomState>::from_iter(
            (0..max_n).into_iter().map_while(|i| {
                proto.input(i).and_then(|p| match p {
                    PrototypeOperand::Register { varnode, .. } => {
                        Some(StackVarDef::from(Var::new0(
                            lifter.register_space_id(),
                            varnode.offset(),
                            varnode.size() as u32 * 8,
                        )))
                    }
                    PrototypeOperand::StackRelative(offset) => {
                        Some(StackVarDef::stack(*offset as _, lifter.address_bytes()))
                    }
                    _ => None,
                })
            }),
        );

        // find greatest uninit in args
        let mut max_arg = None;

        for uninits in self.blocks.values() {
            for uninit in uninits.uninit_uses().values().flatten() {
                if let Some(arg) = args.get_index_of(uninit) {
                    let curr = max_arg.get_or_insert(0);
                    *curr = arg.max(*curr);
                }
            }
        }

        if let Some(max_arg) = max_arg {
            args.into_iter().take(max_arg + 1).collect()
        } else {
            Vec::with_capacity(0)
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct UninitUses {
    mapping: AHashMap<FunctionId, FunctionUninitUses>,
}

impl UninitUses {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn mapping(&self) -> &AHashMap<FunctionId, FunctionUninitUses> {
        &self.mapping
    }

    #[inline]
    pub fn analyse_function(
        project: &Project,
        f: &Function,
        defs: &FunctionReachingStackDefs,
        accesses: &FunctionStackRefs,
    ) -> FunctionUninitUses {
        Self::analyse_function_with(project, f, defs, accesses, None)
    }

    #[inline]
    pub fn analyse_function_with<'a>(
        project: &'a Project,
        f: &'a Function,
        defs: &'a FunctionReachingStackDefs,
        accesses: &'a FunctionStackRefs,
        block_accesses: impl Into<Option<&'a FunctionStackAccesses>>,
    ) -> FunctionUninitUses {
        let lifter = project.lifter();
        let functions = project.functions();
        let injections = project.injections();

        let mut uses = FunctionUninitUses::default();

        match block_accesses.into() {
            Some(block_accesses) => {
                for blk in f.blocks_with(project.code_blocks()) {
                    let id = blk.id();

                    let d = &defs.blocks()[&blk.id()];
                    let a = &block_accesses.blocks()[&id];

                    let mut v = UninitUsesVisitor::new(project.lifter(), d.incoming(), &a);
                    v.eval_block(blk);

                    uses.blocks.insert(
                        id,
                        BlockUninitUses {
                            uninit_uses: v.rsmapping,
                        },
                    );
                }
            }
            None => {
                let mut access_visitor = StackAccessVisitor::new(lifter, functions, injections);

                for blk in f.blocks_with(project.code_blocks()) {
                    let id = blk.id();

                    let d = &defs.blocks()[&blk.id()];
                    let a = access_visitor.analyse_block(&accesses.blocks()[&id], blk);

                    let mut v = UninitUsesVisitor::new(project.lifter(), d.incoming(), &a);
                    v.eval_block(blk);

                    uses.blocks.insert(
                        id,
                        BlockUninitUses {
                            uninit_uses: v.rsmapping,
                        },
                    );
                }
            }
        };

        let mut access_visitor = StackAccessVisitor::new(lifter, functions, injections);

        for blk in f.blocks_with(project.code_blocks()) {
            let id = blk.id();

            let d = &defs.blocks()[&blk.id()];
            let a = access_visitor.analyse_block(&accesses.blocks()[&id], blk);

            let mut v = UninitUsesVisitor::new(project.lifter(), d.incoming(), &a);
            v.eval_block(blk);

            uses.blocks.insert(
                id,
                BlockUninitUses {
                    uninit_uses: v.rsmapping,
                },
            );
        }

        uses
    }
}
