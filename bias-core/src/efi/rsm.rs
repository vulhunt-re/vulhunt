use once_cell::sync::Lazy;
use petgraph::visit::EdgeRef;

use crate::lazy_ustr;
use crate::prelude::visit::*;
use crate::prelude::*;

pub const EFI_RSM_RSB_STUFFING: Uuid = uuid("770A99B7-FBD6-4944-9AB6-414B1AAF8C7A");

// this value means that one parent block
// can fit between RSM and RSB stuffing
const MAX_DEPTH: isize = 1;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct RsmRsbStuffingAnalyser {
    rsm_blocks: AHashSet<CodeBlockId>,
    rsm_stuffed: AHashSet<FunctionId>,
    rsm_unstuffed: AHashSet<FunctionId>,
    filter_multi_in: bool,
}

impl Default for RsmRsbStuffingAnalyser {
    fn default() -> Self {
        Self {
            rsm_blocks: Default::default(),
            rsm_stuffed: Default::default(),
            rsm_unstuffed: Default::default(),
            filter_multi_in: false,
        }
    }
}

static RSM_INTRINSIC: Lazy<Ustr> = lazy_ustr!("smm_restore_state");
static RSB_STUFFING: Lazy<[Ustr; 3]> = Lazy::new(|| [ustr("pause"), ustr("lfence"), ustr("ud2")]);

impl RsmRsbStuffingAnalyser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with(filter_multi_in: bool) -> Self {
        Self {
            filter_multi_in,
            ..Default::default()
        }
    }

    pub fn rsm_blocks(&self) -> &AHashSet<CodeBlockId> {
        &self.rsm_blocks
    }

    pub fn rsm_stuffed(&self) -> &AHashSet<FunctionId> {
        &self.rsm_stuffed
    }

    pub fn rsm_unstuffed(&self) -> &AHashSet<FunctionId> {
        &self.rsm_unstuffed
    }

    pub fn found_unstuffed(&self) -> bool {
        !self.rsm_unstuffed.is_empty()
    }
}

pub struct VisitIntrinsicCount<'a> {
    pattern: &'a [Ustr],
    counter: usize,
}

impl<'a> VisitIntrinsicCount<'a> {
    pub fn new(pattern: &'a [Ustr]) -> Self {
        Self {
            pattern,
            counter: 0,
        }
    }

    pub fn check_and_update(&mut self, name: impl Into<Ustr>) {
        let name = name.into();
        if self.pattern.contains(&name) {
            self.counter += 1;
        }
    }

    pub fn reset(&mut self) {
        self.counter = 0;
    }

    pub fn count(&self) -> usize {
        self.counter
    }

    pub fn found(&self) -> bool {
        self.count() > 0
    }
}

impl<'a, 'ir> Visit<'ir> for VisitIntrinsicCount<'a> {
    fn visit_intrinsic(&mut self, name: &'static str, _args: &'ir [Term<Expr>], _bits: u32) {
        self.check_and_update(name)
    }
}

impl AnalysisInfo for RsmRsbStuffingAnalyser {
    const NAME: &'static str = "RSM RSB Stuffing Analyser";
    const UUID: uuid::Uuid = EFI_RSM_RSB_STUFFING;
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[];
}

impl RsmRsbStuffingAnalyser {
    fn check_stuffing(
        &mut self,
        block: &CodeBlock,
        fid: FunctionId,
        rsb_check: &mut VisitIntrinsicCount,
        project: &Project,
        depth: isize,
    ) -> Result<(), AnalysisError> {
        tracing::debug!("checking block at {}", block.address());

        if depth < 0 {
            tracing::debug!("reached maximum check depth");
            return Ok(());
        }

        let icfg = project.icfg();
        let code_blocks = project.code_blocks();

        // incoming into block in a loop/seq. that stuffs the RSB

        let node = block.node();

        if self.filter_multi_in {
            if icfg.edges_directed(node, Direction::Incoming).count() > 1 {
                tracing::debug!("filtering RSM due to multiple incoming blocks");
                return Ok(());
            }
        }

        for px in icfg.edges_directed(node, Direction::Incoming) {
            let pblock = &code_blocks[icfg[px.source()]];

            tracing::debug!("checking incoming block {}", pblock.address());

            for sx in icfg.edges_directed(pblock.node(), Direction::Incoming) {
                let sblock = &code_blocks[icfg[sx.source()]];

                tracing::debug!("checking stuffing for block {}", sblock.address());

                if !sx.weight().is_call() {
                    tracing::debug!("found intermediate block: {}", sblock.address());
                    // assume that it is a new RSM block and check that it is stuffed
                    self.check_stuffing(sblock, fid, rsb_check, project, depth - 1)?;
                    continue;
                }

                let snblock_addr = sblock.next_address();

                if let Some(snblock) = code_blocks.get_point(&snblock_addr) {
                    snblock.visit(rsb_check);
                    if rsb_check.found() {
                        self.rsm_stuffed.insert(fid);
                        return Ok(());
                    }

                    rsb_check.reset();
                } else {
                    tracing::debug!("fall of call not part of ICFG");
                }
            }
        }

        Ok(())
    }
}

impl Analysis for RsmRsbStuffingAnalyser {
    fn id(&self) -> &Uuid {
        &EFI_RSM_RSB_STUFFING
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let rsm_intrinsic = &[*RSM_INTRINSIC];
        let mut rsm_check = VisitIntrinsicCount::new(rsm_intrinsic);
        let mut rsm_funcs = AHashSet::new();

        for block in project.code_blocks().values() {
            // check if block contains rsm
            block.visit(&mut rsm_check);
            if rsm_check.found() {
                self.rsm_blocks.insert(block.id());
                rsm_funcs.insert((block, block.function()));
                rsm_check.reset();
            }
        }

        let mut rsb_check = VisitIntrinsicCount::new(&*RSB_STUFFING);

        for (block, fid) in rsm_funcs.into_iter() {
            tracing::debug!("checking RSM at {}", block.address());
            self.check_stuffing(block, fid, &mut rsb_check, project, MAX_DEPTH)?;

            if !self.rsm_stuffed.contains(&fid) {
                self.rsm_unstuffed.insert(fid);
            }
        }

        Ok(())
    }
}
