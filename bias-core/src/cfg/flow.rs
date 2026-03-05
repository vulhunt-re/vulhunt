bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
    pub struct FlowInfo: u16 {
        const FALL        = 0b0000_0000_0000_0001;
        const BRANCH      = 0b0000_0000_0000_0010;
        const CALL        = 0b0000_0000_0000_0100;
        const RETURN      = 0b0000_0000_0000_1000;

        const INDIRECT    = 0b0000_0000_0001_0000;

        const BRANCH_DEST = 0b0000_0000_0010_0000;
        const CALL_DEST   = 0b0000_0000_0100_0000;

        // 1. instruction's address referenced as an immediate
        //    on the rhs of an assignment
        // 2. the instruction is a fall from padding
        const MAYBE_TAKEN = 0b0000_0000_1000_0000;

        // instruction is a semantic NO-OP
        const NOP         = 0b0000_0001_0000_0000;

        // instruction is a trap (e.g., UD2)
        const TRAP        = 0b0000_0010_0000_0000;

        // instruction falls into invalid
        const INVALID     = 0b0000_0100_0000_0000;

        // is contained within a function
        const IN_FUNCTION = 0b0000_1000_0000_0000;

        // is jump table target
        const IN_TABLE    = 0b0001_0000_0000_0000;

        // treat as invalid if repeated
        const NONSENSE    = 0b0010_0000_0000_0000;

        const HALT        = 0b0100_0000_0000_0000;

        // hinted to us by the loader--we don't consider it invalid
        const HINT        = 0b1000_0000_0000_0000;

        const UNVIABLE    = Self::TRAP.bits() | Self::INVALID.bits();

        const DEST        = Self::BRANCH_DEST.bits() | Self::CALL_DEST.bits();
        const FLOW        = Self::BRANCH.bits() | Self::CALL.bits() | Self::RETURN.bits();

        const TAKEN       = Self::DEST.bits() | Self::MAYBE_TAKEN.bits();
    }
}

impl Default for FlowInfo {
    fn default() -> Self {
        FlowInfo::INVALID
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum FlowKind {
    Branch,
    CBranch,
    IBranch,
    Call,
    ICall,
    ServiceCall,
    Return,
    Fall,
    SwitchBranch,
    SwitchCall,
    TailCallBranch,
}

impl FlowKind {
    pub fn is_branch(&self) -> bool {
        matches!(self, Self::Branch | Self::CBranch | Self::IBranch)
    }

    pub fn is_call(&self) -> bool {
        matches!(
            self,
            Self::Call | Self::ICall | Self::ServiceCall | Self::SwitchCall | Self::TailCallBranch
        )
    }

    pub fn is_conditional(&self) -> bool {
        matches!(self, Self::CBranch)
    }

    pub fn is_fall(&self) -> bool {
        matches!(self, Self::Fall)
    }

    pub fn is_indirect(&self) -> bool {
        matches!(self, Self::ICall | Self::IBranch)
    }

    pub fn is_return(&self) -> bool {
        matches!(self, Self::Return)
    }

    pub fn is_switch(&self) -> bool {
        matches!(self, Self::SwitchBranch)
    }
}
