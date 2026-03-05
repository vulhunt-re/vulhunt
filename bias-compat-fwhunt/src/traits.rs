use bias_core::Project;

use crate::matcher::MatchContext;

pub trait MatchesRule {
    fn is_group(&self) -> bool { false }

    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool;

    #[allow(unused)]
    fn matches_bytes(&self, context: &mut MatchContext, bytes: &[u8]) -> bool {
        false
    }
}
