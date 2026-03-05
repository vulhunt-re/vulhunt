use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::iter;
use std::marker::PhantomData;
use std::path::Path;
use std::rc::Rc;

use bias_core::prelude::*;

use bias_core::decompiler::{Decompiler, DecompilerConfig, DefaultDecompilerResolver};

use bias::component::LoadedBinaryComponent;
use bias::platform::common::flirt::{FLIRTSymbolManager, FunctionSymbolMapping};
use bias::platform::common::types::{FunctionTypeMapping, TypeManager};
use bias::platform::PlatformAttributes;

use bias::util::tags::BlobTag;

use crate::lua::api::CallSiteContext;
use crate::lua::project::PlatformApi;
use crate::lua::scope::{AnnotatingPlatformTypeResolver, CheckScopeFunction};
use crate::lua::{
    CheckResult, CheckScope, Checker, CheckerContext, CheckerError, FunctionContext, ProjectHandle,
};
use crate::{CheckerDB, VulHuntModuleDir};

type ScopeMap<'a> =
    AHashMap<(Option<&'a str>, BlobTag, &'a CheckScope), Vec<(usize, &'a CheckScopeFunction)>>;

type TypeCacheKey<'a> = (Option<&'a str>, BlobTag);

pub struct Engine<'a, P>
where
    P: for<'engine> PlatformApi<'engine>,
{
    project: &'a Project,
    scopes: ScopeMap<'a>, // (typeid, scope) -> (id, fcn)
    checkers: Vec<&'a Checker>,
    contexts: Vec<Option<CheckerContext>>,
    flirt_signature_entries: &'a BTreeMap<BlobTag, BTreeSet<String>>,
    flirt_symbols: FLIRTSymbolManager,
    flirt_symbols_cache: BTreeMap<BlobTag, FunctionSymbolMapping>,
    types: TypeManager,
    types_cache: BTreeMap<TypeCacheKey<'a>, FunctionTypeMapping>,
    decompiler_config: DecompilerConfig,
    module_dir: VulHuntModuleDir,
    _marker: PhantomData<fn() -> P>,
}

impl<'a, P> Engine<'a, P>
where
    P: for<'engine> PlatformApi<'engine>,
{
    pub fn new(
        component: &LoadedBinaryComponent<'_>,
        project: &'a Project,
        checkers: &'a CheckerDB,
        symbols: FLIRTSymbolManager,
        types: TypeManager,
        module_dir: impl Into<VulHuntModuleDir>,
    ) -> Self {
        Self::new_with(
            component,
            project,
            checkers,
            symbols,
            types,
            module_dir,
            DecompilerConfig::default(),
        )
    }

    pub fn new_with(
        component: &LoadedBinaryComponent<'_>,
        project: &'a Project,
        checkers: &'a CheckerDB,
        symbols: FLIRTSymbolManager,
        types: TypeManager,
        module_dir: impl Into<VulHuntModuleDir>,
        decompiler_config: DecompilerConfig,
    ) -> Self {
        let mut scopes = AHashMap::<_, Vec<_>>::new();
        let attributes = component.container();

        tracing::debug!("loading {} checkers", checkers.len());

        let flirt_signature_entries = &checkers.signature_files;

        let checkers = checkers
            .iter()
            .filter(|checker| {
                checker.platform() == component.platform() && {
                    match P::should_check(checker.architecture(), checker.conditions(), &attributes)
                        .and_then(|should_check| {
                            if should_check {
                                checker.conditions().validate(component)
                            } else {
                                Ok(should_check)
                            }
                        }) {
                        Ok(should_check) => should_check,
                        Err(e) => {
                            tracing::debug!("not applying checker `{}`: {e}", checker.name());
                            false
                        }
                    }
                }
            })
            .enumerate()
            .map(|(i, checker)| {
                let tlib = checker.types();

                // NOTE: It is possible that there are no applicable FLIRT libs
                // available for a given checker under the current platform.
                // In which case, we return a default BlobTag, which will be the
                // same for all checkers with no FLIRT libs defined.
                let stag = checker
                    .signature_arch_tags()
                    .get(project.lifter().translator().architecture())
                    .copied()
                    .unwrap_or_default();

                for scope in checker.scopes() {
                    scopes
                        .entry((tlib, stag, scope))
                        .or_default()
                        .push((i, scope.with()));
                }
                checker
            })
            .collect::<Vec<_>>();

        let mut contexts = Vec::with_capacity(checkers.len());
        contexts.resize_with(checkers.len(), || None);

        Self {
            project,
            scopes,
            checkers,
            contexts,
            flirt_signature_entries,
            flirt_symbols: symbols,
            flirt_symbols_cache: Default::default(),
            types,
            types_cache: Default::default(),
            module_dir: module_dir.into(),
            decompiler_config,
            _marker: PhantomData,
        }
    }

    fn context_for<'b>(
        checker: &'b Checker,
        context: &'b mut Option<CheckerContext>,
        module_dir: Option<&Path>,
    ) -> Result<&'b mut CheckerContext, CheckerError> {
        // We want Option::try_replace_with :)
        match context {
            None => {
                let ctxt = checker.context(module_dir)?;
                *context = Some(ctxt);
                Ok(context.as_mut().unwrap())
            }
            Some(ref mut ctxt) => Ok(ctxt),
        }
    }

    pub fn checker_for(&self, id: usize) -> Option<&Checker> {
        self.checkers.get(id).copied()
    }

    pub fn symbols_for(&self, id: usize) -> Option<&FunctionSymbolMapping> {
        let checker = self.checker_for(id)?;
        let tag = checker
            .signature_arch_tags()
            .get(self.project.lifter().translator().architecture())?;
        self.flirt_symbols_cache.get(tag)
    }

    pub fn types_for(&self, id: usize) -> Option<&FunctionTypeMapping> {
        let checker = self.checker_for(id)?;
        let tag = checker
            .signature_arch_tags()
            .get(self.project.lifter().translator().architecture())
            .copied()
            .unwrap_or_default();
        let tkey = (checker.types(), tag);
        self.types_cache.get(&tkey)
    }

    fn build_caches(&mut self) -> Result<(), CheckerError> {
        for ((tlib, stag, _), _) in self.scopes.iter() {
            // NOTE: here we need to build the appropriate signature mapping. This will be the same
            // mapping for check contexts with the same signature tag, so we can take a
            // representative checker, and it's signature configuration will work for all in the
            // same (typing, signatures) grouping:
            //

            let symbols = match self.flirt_symbols_cache.entry(*stag) {
                Entry::Vacant(entry) => {
                    if let Some(entries) = self.flirt_signature_entries.get(stag) {
                        entry.insert(
                            self.flirt_symbols
                                .function_symbol_mapping(entries.iter(), self.project)?,
                        )
                    } else {
                        entry.insert(
                            self.flirt_symbols
                                .function_symbol_mapping(iter::empty::<String>(), self.project)?,
                        )
                    }
                }
                Entry::Occupied(entry) => entry.into_mut(),
            };

            // NOTE: next we produce the type map for this set of checkers (if there is one)
            //
            // It's possible we have no type library, but we also (by the default type library
            // association) have symbols via FLIRT that can be typed. So we also handle that case
            // now.
            //
            let tkey = (*tlib, *stag);
            if let Entry::Vacant(entry) = self.types_cache.entry(tkey) {
                let tmap = if let Some(tlib) = tlib {
                    self.types
                        .function_type_mapping(tlib, self.project)
                        .map(|tmap| entry.insert(tmap))?
                } else {
                    entry.insert(FunctionTypeMapping::from_project(self.project))
                };

                // Lastly, make sure that we have types for any FLIRT identified symbols.
                //
                // NOTE: This won't update the mapping in TypeDB such that we have an association
                // of addr -> type based on the type mapping, so we need to keep this in mind
                // within our AnnotatingPlatformTypeResolver.
                //
                symbols.update_type_mapping(tmap);
            }
        }
        Ok(())
    }

    pub fn run<'engine, 'attrs>(
        &'engine mut self,
        attrs: &'attrs PlatformAttributes<'a>,
    ) -> Result<Vec<CheckResult>, CheckerError> {
        self.build_caches()?;

        let mut decompiler = None;
        let mut checks = Vec::new();

        for ((tlib, stag, scope), checkers) in self.scopes.iter() {
            let symbols = &self.flirt_symbols_cache[stag];
            let tkey = (*tlib, *stag);
            let tmap = &self.types_cache[&tkey];

            match scope {
                CheckScope::Calls(c) => {
                    // NOTE: we may have imp.f specified, if so we will look for both imp.f and f
                    // and merge the candidates.
                    //
                    // find all functions that call c.to()
                    let (all_to, with_jumps) = c.to().targets_with(self.project, symbols, true)?;

                    let functions = self.project.functions();
                    let blocks = self.project.code_blocks();
                    let icfg = self.project.icfg();

                    for to in all_to {
                        let entry = blocks[to.entry()].node();
                        let mut candidates = BTreeMap::<_, Vec<_>>::new();

                        for (fid, blk) in icfg
                            .edges_directed(entry, Direction::Incoming)
                            .filter_map(|edge| {
                                if edge.weight().is_call()
                                    || (with_jumps && edge.weight().is_branch())
                                {
                                    let blk = &blocks[icfg[edge.source()]];
                                    let fid = blk.function();
                                    Some((fid, blk))
                                } else {
                                    None
                                }
                            })
                        {
                            candidates.entry(fid).or_default().push(blk);
                        }

                        if candidates.is_empty() {
                            // nothing to check beyond here
                            continue;
                        }

                        let resolver = AnnotatingPlatformTypeResolver::new_with(
                            P::type_resolver(self.project),
                            self.project,
                            Cow::Borrowed(c.annotations()),
                            symbols,
                            tmap.types(),
                        );

                        for (fid, blks) in candidates {
                            let f = &functions[fid];

                            let fctx = FunctionContext::new_with(f, self.project, &*symbols);

                            // NOTE: the clone is cheap--just a few pointers
                            if !c.eval_where(fctx.clone())? {
                                continue;
                            }

                            let aliases = Rc::new(TypedAliases::analyse_function_with(
                                &*self.project,
                                f,
                                &resolver,
                            ));

                            for blk in blks {
                                let bid = blk.id();
                                let aliases = &aliases.blocks()[&bid];

                                for (idx, handler) in checkers {
                                    let checker = &self.checkers[*idx];
                                    let context = Self::context_for(
                                        checker,
                                        &mut self.contexts[*idx],
                                        self.module_dir.as_deref(),
                                    )?;

                                    let mut handle =
                                        ProjectHandle::<P>::new(&*self.project, &*symbols, &*tmap);

                                    if checker.extensions().requires_decompiler() {
                                        let mut decompiler = match decompiler {
                                            None => decompiler.insert(
                                                Decompiler::new_with_config(
                                                    &*self.project,
                                                    self.project.type_db(),
                                                    DefaultDecompilerResolver::default(),
                                                    self.decompiler_config.clone(),
                                                )
                                                .map_err(CheckerError::decompiler)?,
                                            ),
                                            Some(ref mut decompiler) => {
                                                decompiler
                                                    .clear()
                                                    .map_err(CheckerError::decompiler)?;
                                                decompiler
                                            }
                                        };
                                        P::configure_decompiler(
                                            &mut decompiler,
                                            self.project,
                                            attrs,
                                            Some(symbols),
                                            Some(tmap),
                                        )?;
                                        handle.set_decompiler(decompiler);
                                    }

                                    let ctx = CallSiteContext::new(
                                        self.project,
                                        f,
                                        blk,
                                        aliases,
                                        symbols,
                                        tmap.types(),
                                    );

                                    let Some(result) = context.calls(handler, handle, ctx)? else {
                                        continue;
                                    };

                                    checks.push(result.with_rule(*idx));
                                }
                            }
                        }
                    }
                }
                CheckScope::FunctionWith(c) => {
                    if let Some(to) = c.target() {
                        let all_to = to.targets_with(self.project, symbols, true)?;

                        for f in all_to {
                            for (idx, handler) in checkers {
                                let checker = &self.checkers[*idx];
                                let mut handle =
                                    ProjectHandle::<P>::new(self.project, &*symbols, &*tmap);
                                if checker.extensions().requires_decompiler() {
                                    let mut decompiler = match decompiler {
                                        None => decompiler.insert(
                                            Decompiler::new_with_config(
                                                &*self.project,
                                                self.project.type_db(),
                                                DefaultDecompilerResolver::default(),
                                                self.decompiler_config.clone(),
                                            )
                                            .map_err(CheckerError::decompiler)?,
                                        ),
                                        Some(ref mut decompiler) => {
                                            decompiler.clear().map_err(CheckerError::decompiler)?;
                                            decompiler
                                        }
                                    };
                                    P::configure_decompiler(
                                        &mut decompiler,
                                        &*self.project,
                                        attrs,
                                        Some(symbols),
                                        Some(tmap),
                                    )?;
                                    handle.set_decompiler(decompiler);
                                }
                                let context = Self::context_for(
                                    checker,
                                    &mut self.contexts[*idx],
                                    self.module_dir.as_deref(),
                                )?;
                                let Some(result) = context.function_with(
                                    handler,
                                    handle,
                                    FunctionContext::new_with(f, self.project, &*symbols),
                                )?
                                else {
                                    continue;
                                };
                                checks.push(result.with_rule(*idx));
                            }
                        }
                    } else if c.target().is_none() {
                        tracing::trace!("analysing all functions");

                        for f in self.project.functions().values() {
                            for (idx, handler) in checkers {
                                let checker = &self.checkers[*idx];
                                let mut handle =
                                    ProjectHandle::<P>::new(self.project, &*symbols, &*tmap);
                                if checker.extensions().requires_decompiler() {
                                    let mut decompiler = match decompiler {
                                        None => decompiler.insert(
                                            Decompiler::new_with_config(
                                                &*self.project,
                                                self.project.type_db(),
                                                DefaultDecompilerResolver::default(),
                                                self.decompiler_config.clone(),
                                            )
                                            .map_err(CheckerError::decompiler)?,
                                        ),
                                        Some(ref mut decompiler) => {
                                            decompiler.clear().map_err(CheckerError::decompiler)?;
                                            decompiler
                                        }
                                    };
                                    P::configure_decompiler(
                                        &mut decompiler,
                                        &*self.project,
                                        attrs,
                                        Some(symbols),
                                        Some(tmap),
                                    )?;
                                    handle.set_decompiler(decompiler);
                                }
                                let context = Self::context_for(
                                    checker,
                                    &mut self.contexts[*idx],
                                    self.module_dir.as_deref(),
                                )?;
                                let Some(result) = context.function_with(
                                    handler,
                                    handle,
                                    FunctionContext::new_with(f, self.project, &*symbols),
                                )?
                                else {
                                    continue;
                                };
                                checks.push(result.with_rule(*idx));
                            }
                        }
                    }
                }
                CheckScope::ProjectWith(_) => {
                    for (idx, handler) in checkers {
                        let checker = &self.checkers[*idx];
                        let mut handle = ProjectHandle::<P>::new(self.project, &*symbols, &*tmap);
                        if checker.extensions().requires_decompiler() {
                            let mut decompiler = match decompiler {
                                None => decompiler.insert(
                                    Decompiler::new_with_config(
                                        &*self.project,
                                        self.project.type_db(),
                                        DefaultDecompilerResolver::default(),
                                        self.decompiler_config.clone(),
                                    )
                                    .map_err(CheckerError::decompiler)?,
                                ),
                                Some(ref mut decompiler) => {
                                    decompiler.clear().map_err(CheckerError::decompiler)?;
                                    decompiler
                                }
                            };
                            P::configure_decompiler(
                                &mut decompiler,
                                &*self.project,
                                attrs,
                                Some(symbols),
                                Some(tmap),
                            )?;
                            handle.set_decompiler(decompiler);
                        }
                        let context = Self::context_for(
                            checker,
                            &mut self.contexts[*idx],
                            self.module_dir.as_deref(),
                        )?;
                        let Some(result) = context.project_with(handler, handle)? else {
                            continue;
                        };
                        checks.push(result.with_rule(*idx));
                    }
                }
            }
        }

        Ok(checks)
    }
}
