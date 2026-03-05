use std::collections::BTreeSet;

use bias_core::prelude::*;

use crate::schema::FwHuntCheckMatch;
use crate::MatchesRule;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Match {
    group: bool,
    provenance: BTreeSet<Address>,
    description: Option<FwHuntCheckMatch>,
}

impl Match {
    pub fn new<T>(matcher: &T) -> Self
    where
        T: MatchesRule,
    {
        Self {
            group: matcher.is_group(),
            provenance: BTreeSet::default(),
            description: None,
        }
    }

    #[inline]
    pub fn is_group(&self) -> bool {
        self.group
    }

    #[inline]
    pub fn has_provenance(&self) -> bool {
        !self.provenance.is_empty()
    }

    #[inline]
    pub fn provenance<'b>(&'b self) -> impl ExactSizeIterator<Item = Address> + 'b {
        self.provenance.iter().copied()
    }

    #[inline]
    pub fn description(&self) -> Option<&FwHuntCheckMatch> {
        self.description.as_ref()
    }

    #[inline]
    pub fn description_mut(&mut self) -> Option<&mut FwHuntCheckMatch> {
        self.description.as_mut()
    }

    #[inline]
    pub fn explain<'b>(
        &'b self,
    ) -> impl Iterator<Item = (Address, Option<&'b FwHuntCheckMatch>)> + 'b {
        self.provenance
            .iter()
            .copied()
            .zip(std::iter::repeat(self.description.as_ref()))
    }
}

impl<T> From<&'_ T> for Match
where
    T: MatchesRule,
{
    fn from(matcher: &T) -> Self {
        Self::new(matcher)
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct MatchContext {
    commits: Vec<Match>,
    pending: Vec<Match>,
}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct MatchCheckpoint(usize);

impl MatchContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn begin(&mut self, matcher: impl Into<Match>) -> MatchCheckpoint {
        let commits = self.commits.len();
        self.pending.push(matcher.into());

        MatchCheckpoint(commits)
    }

    pub fn discard(&mut self, checkpoint: MatchCheckpoint) {
        self.commits.truncate(checkpoint.0);
        self.pending.pop();
    }

    pub fn commit(&mut self, checkpoint: MatchCheckpoint) {
        if let Some(last) = self.pending.pop() {
            if !last.is_group() || checkpoint.0 != self.commits.len() {
                self.commits.push(last);
            }
        }
    }

    pub fn commits(&self) -> impl ExactSizeIterator<Item = &Match> {
        self.commits.iter()
    }

    pub fn principal_commit(&self) -> Option<&Match> {
        self.commits.last()
    }

    pub fn push_provenance(&mut self, addr: impl Into<Address>) {
        if let Some(last) = self.pending.last_mut() {
            last.provenance.insert(addr.into());
        }
    }

    pub fn pending_provenance(&self) -> Option<Address> {
        if let Some(last) = self.pending.last() {
            last.provenance.last().copied()
        } else {
            None
        }
    }

    pub fn pending_provenance_iter<'a>(&'a self) -> impl Iterator<Item = Address> + 'a {
        self.pending
            .last()
            .into_iter()
            .flat_map(|last| last.provenance())
    }

    pub fn extend_provenance(&mut self, iter: impl Iterator<Item = Address>) {
        if let Some(last) = self.pending.last_mut() {
            last.provenance.extend(iter);
        }
    }

    pub fn describe(&mut self, description: FwHuntCheckMatch) {
        if let Some(last) = self.pending.last_mut() {
            last.description = Some(description);
        }
    }

    pub fn explain<'b>(
        &'b self,
    ) -> impl Iterator<Item = (Address, Option<&'b FwHuntCheckMatch>)> + 'b {
        self.commits.iter().map(|commit| commit.explain()).flatten()
    }
}
