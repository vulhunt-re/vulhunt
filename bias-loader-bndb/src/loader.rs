use bias::component::{ComponentLoaderError, LoadedBinaryComponent};
use bias::platform::{
    PlatformComponentBinaryData, PlatformComponentBinaryLoader,
    PlatformComponentGuidedBinaryLoader, PlatformComponentLoader, PlatformError,
};
use bias::util::BytesOrMapping;
use bias_core::ProjectConfig;
use bias_core::arch::ContextUpdates;
use bias_core::arch::arm::TMODE_CONTEXT;
use bias_core::cfg::{GuidedFunctionEntry, GuidedICFGBuilder};
use bias_core::kb::function::FunctionInfo;
use bias_core::lifter::Lifter;
use bias_core::loader::LoadedBinary;
use bias_core::loader::elf::ELFExternalSymbolsRef;
use bias_core::prelude::{Address, FlowKind, Identifiable, LanguageDB};
use bias_core::project::Project;
use bias_core::region::Memory;
use binaryninja::binary_view::BinaryViewExt;
use binaryninja::flowgraph::BranchType;

use crate::loaded_binary::BinaryViewRef;
use crate::util::{is_thumb_mode, normalise_arm_address};

pub struct BNDBBinaryLoader;

impl BNDBBinaryLoader {
    pub const fn platform_loader() -> PlatformComponentLoader {
        PlatformComponentLoader::GuidedBinary(&Self)
    }
}

impl PlatformComponentBinaryLoader for BNDBBinaryLoader {
    fn load_bytes<'data, 'bytes>(
        &self,
        _ldb: &LanguageDB,
        _bytes: &'data BytesOrMapping<'bytes>,
    ) -> Result<PlatformComponentBinaryData<'data>, ComponentLoaderError> {
        Err(ComponentLoaderError::custom_with(
            "Binary Ninja databases cannot be loaded from a buffer",
        ))
    }
}

impl PlatformComponentGuidedBinaryLoader for BNDBBinaryLoader {
    fn load_project(
        &self,
        binary: &LoadedBinaryComponent<'_>,
        lifter: Lifter,
        _config: &ProjectConfig,
    ) -> Result<Project, PlatformError> {
        let container = binary.container();
        let view = container.get_attr::<BinaryViewRef>().ok_or_else(|| {
            PlatformError::project_with("missing BinaryView in component container")
        })?;
        let xtrns = container
            .get_attr::<ELFExternalSymbolsRef>()
            .ok_or_else(|| {
                PlatformError::project_with("missing ELF external symbols in component container")
            })?;

        let arch = lifter.arch();
        let is_arm = matches!(arch.id(), bias_core::arch::arm::ARCH_ARM);
        let address_size = lifter.address_bytes();

        let mut project = Project::new_empty(binary, lifter);
        let mut guide = GuidedICFGBuilder::new(&mut project);

        for func in view.functions().iter() {
            let func_addr = func.start();
            let context = is_arm
                .then(|| ContextUpdates::single(TMODE_CONTEXT, is_thumb_mode(func_addr) as u32));

            for block in func.basic_blocks().iter() {
                let start = normalise_arm_address(block.start(), is_arm);
                let len = (block.end() - block.start()) as usize;
                guide.schedule_mapped_block_with_context(start, len, context.clone());
            }
        }

        for (addr, _) in xtrns.iter() {
            guide.schedule_mapped_block(addr, address_size);
        }

        let mut guide = guide.finalise();

        for func in view.functions().iter() {
            let raw_addr = func.start();
            let can_return = func.can_return();

            let mut properties = FunctionInfo::default();
            if !can_return.contents {
                properties |= FunctionInfo::NON_RETURNING;
            }

            let entry = if is_arm {
                let is_thumb = is_thumb_mode(raw_addr);
                if is_thumb {
                    properties |= FunctionInfo::TMODE;
                }
                let context = ContextUpdates::single(TMODE_CONTEXT, is_thumb as u32);
                GuidedFunctionEntry::new(properties, context)
            } else {
                GuidedFunctionEntry::new(properties, ContextUpdates::default())
            };

            let entry_addr = normalise_arm_address(raw_addr, is_arm);
            guide.mark_function_with(entry_addr, entry);

            for block in func.basic_blocks().iter() {
                let block_addr = normalise_arm_address(block.start(), is_arm);
                guide.mark_block(block_addr);
            }
        }

        for (addr, _name) in xtrns.iter() {
            let entry = GuidedFunctionEntry::new(FunctionInfo::EXTERN, ContextUpdates::default());
            guide.mark_function_with(addr, entry);
        }

        let mut guide = guide.finalise();

        for func in view.functions().iter() {
            let raw_addr = func.start();
            let func_addr = normalise_arm_address(raw_addr, is_arm);

            for code_ref in view.code_refs_to_addr(raw_addr).iter() {
                guide.mark_flow(code_ref.address, raw_addr, FlowKind::Call);
            }

            for block in func.basic_blocks().iter() {
                let block_addr = normalise_arm_address(block.start(), is_arm);
                guide.force_block_assoc(func_addr, block_addr);

                let src = block.end() - 1;
                for edge in block.outgoing_edges().iter() {
                    let dst = edge.target.start();
                    let kind = match edge.branch {
                        BranchType::TrueBranch => FlowKind::CBranch,
                        BranchType::FalseBranch => FlowKind::Fall,
                        BranchType::UnconditionalBranch
                        | BranchType::UserDefinedBranch
                        | BranchType::UnresolvedBranch => FlowKind::Branch,
                        BranchType::IndirectBranch => FlowKind::IBranch,
                        _ => continue,
                    };
                    guide.mark_flow(src, dst, kind);
                }
            }
        }

        for (addr, _name) in xtrns.iter() {
            for code_ref in view.code_refs_to_addr(addr.offset()).iter() {
                guide.mark_flow(code_ref.address, addr, FlowKind::Call);
            }
        }

        guide.finalise();

        let is_plt_got = |memory: &Memory, addr: Address| {
            memory
                .find_region(addr)
                .is_some_and(|r| r.name().contains(".plt") || r.name().contains(".got"))
        };

        for func in view.functions().iter() {
            let entry = Address::from(func.start());

            if is_plt_got(project.memory(), entry) {
                continue;
            }

            let Some(f) = project.functions_mut().get_point_mut(entry) else {
                continue;
            };

            let name = func.symbol().full_name();

            let Ok(name) = name.to_str() else {
                continue;
            };

            if name.is_empty() || name.starts_with("sub_") {
                continue;
            }

            f.update_name(name);

            let id = f.id();

            project.symbols_mut().insert(name, id);
        }

        let pt = project.tables_mut();

        for func in view.functions().iter() {
            let entry = Address::from(func.start());

            if !is_plt_got(pt.memory, entry) {
                continue;
            }

            let Some(f) = pt.ftable.get_point_mut(entry) else {
                continue;
            };

            let name = func.symbol().full_name();

            let Ok(name) = name.to_str() else {
                continue;
            };

            let id = f.id();

            let name = if pt.symtab.contains(name) {
                pt.symtab
                    .insert_fresh_with_prefix_or_rebind(format!("imp.{name}"), id)
            } else {
                pt.symtab
                    .insert_fresh_with_prefix_or_rebind(format!("imp.{name}"), id);
                pt.symtab.insert_fresh_with_prefix(name, id)
            };

            f.update_name(name);
        }

        for (entry, name) in xtrns.iter() {
            let Some(f) = pt.ftable.get_point_mut(entry) else {
                continue;
            };

            let id = f.id();

            let name = if pt.symtab.contains(name) {
                pt.symtab
                    .insert_fresh_with_prefix_or_rebind(format!("imp.{name}"), id)
            } else {
                pt.symtab.insert_fresh_with_prefix(name, id);
                pt.symtab
                    .insert_fresh_with_prefix_or_rebind(format!("imp.{name}"), id);
                name
            };

            f.update_name(name);
        }

        Ok(project)
    }
}
