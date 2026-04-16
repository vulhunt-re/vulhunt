use std::fmt::Display;

use crate::prelude::*;

use super::SSExprRef;

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SSEValidityState {
    #[default]
    Both,
    ForwardOnly,
    BackwardOnly,
}

impl SSEValidityState {
    pub fn is_both(&self) -> bool {
        matches!(self, Self::Both)
    }

    pub fn is_forward_or_both(&self) -> bool {
        matches!(self, Self::Both | Self::ForwardOnly)
    }

    pub fn is_backward_or_both(&self) -> bool {
        matches!(self, Self::Both | Self::BackwardOnly)
    }

    pub fn is_forward_only(&self) -> bool {
        matches!(self, Self::ForwardOnly)
    }

    pub fn is_backward_only(&self) -> bool {
        matches!(self, Self::BackwardOnly)
    }

    pub fn is_subset_of(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Both, Self::Both)
                | (Self::ForwardOnly, Self::ForwardOnly | Self::Both)
                | (Self::BackwardOnly, Self::BackwardOnly | Self::Both)
        )
    }
}

impl Display for SSEValidityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Both => "both",
            Self::ForwardOnly => "forward",
            Self::BackwardOnly => "backward",
        };
        f.write_str(kind)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SSEValidityLocation(Option<Location>);

impl SSEValidityLocation {
    pub fn new(loc: impl Into<Self>) -> Self {
        loc.into()
    }

    pub fn unbounded() -> Self {
        Self(None)
    }

    pub fn is_unbounded(&self) -> bool {
        self.0.is_none()
    }

    pub fn is_bounded(&self) -> bool {
        self.0.is_some()
    }

    pub fn location(&self) -> Option<Location> {
        self.0
    }

    pub fn upper_bound(&self, other: Self) -> Self {
        match (self.0, other.0) {
            (Some(loc1), Some(loc2)) => Self(Some(loc1.max(loc2))),
            _ => Self(None),
        }
    }

    pub fn lower_bound(&self, other: Self) -> Self {
        match (self.0, other.0) {
            (Some(loc1), Some(loc2)) => Self(Some(loc1.min(loc2))),
            _ => Self(None),
        }
    }

    pub fn in_lower_bound(&self, loc: &Location) -> bool {
        self.0.as_ref().map_or(true, |sloc| *loc >= *sloc)
    }

    pub fn in_upper_bound(&self, loc: &Location) -> bool {
        self.0.as_ref().map_or(true, |sloc| *loc <= *sloc)
    }
}

impl Display for SSEValidityLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(loc) = self.0 {
            write!(f, "{}", loc)
        } else {
            f.write_str("-")
        }
    }
}

impl From<Address> for SSEValidityLocation {
    fn from(addr: Address) -> Self {
        Self(Some(Location::new(addr, 0)))
    }
}

impl From<Location> for SSEValidityLocation {
    fn from(loc: Location) -> Self {
        Self(Some(loc))
    }
}

impl From<Option<Location>> for SSEValidityLocation {
    fn from(loc: Option<Location>) -> Self {
        Self(loc)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SSEValiditySource<'a> {
    location: Location,
    sse: SSExprRef<'a>,
}

impl<'a> SSEValiditySource<'a> {
    pub fn new(location: Location, sse: SSExprRef<'a>) -> Self {
        Self { location, sse }
    }

    pub fn sse(&self) -> SSExprRef<'a> {
        self.sse
    }

    pub fn location(&self) -> Location {
        self.location
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SSEValidity {
    state: SSEValidityState,
    locally_bounded: Option<Address>,
    not_valid_before: SSEValidityLocation,
    not_valid_after: SSEValidityLocation,
}

impl Display for SSEValidity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "valid from {} to {}",
            self.not_valid_before, self.not_valid_after
        )?;
        write!(f, " for {}", self.state)?;
        if let Some(addr) = self.locally_bounded {
            write!(f, "; locally bounded to {addr}")?;
        }
        Ok(())
    }
}

impl SSEValidity {
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.state.is_subset_of(&other.state)
            && match (self.locally_bounded, other.locally_bounded) {
                (_, None) => true,
                (Some(lhs), Some(rhs)) => lhs == rhs,
                (None, Some(_)) => false,
            }
            && match (self.not_valid_before.location(), other.not_valid_before.location()) {
                (_, None) => true,
                (Some(lhs), Some(rhs)) => lhs >= rhs,
                (None, Some(_)) => false,
            }
            && match (self.not_valid_after.location(), other.not_valid_after.location()) {
                (_, None) => true,
                (Some(lhs), Some(rhs)) => lhs <= rhs,
                (None, Some(_)) => false,
            }
    }

    pub(crate) fn bounds(
        loc: Location,
        all: &SSEValiditySet,
    ) -> (SSEValidityLocation, SSEValidityLocation) {
        let mut lower_validity = None;
        let mut upper_validity = None;

        for validity in all.iter() {
            if validity.is_backward_live(&loc) {
                lower_validity = Some(match lower_validity {
                    Some(current) => validity.not_valid_before.lower_bound(current),
                    None => validity.not_valid_before,
                });
                upper_validity = Some(match upper_validity {
                    Some(current) => validity.not_valid_after.upper_bound(current),
                    None => validity.not_valid_after,
                });
            }
        }

        (
            lower_validity.unwrap_or_else(SSEValidityLocation::unbounded),
            upper_validity.unwrap_or_else(SSEValidityLocation::unbounded),
        )
    }

    pub fn forward(state: SSEValidityState, loc: Location) -> Self {
        Self {
            state,
            not_valid_before: SSEValidityLocation::new(loc),
            not_valid_after: SSEValidityLocation::unbounded(),
            locally_bounded: None,
        }
    }

    pub fn forward_unbounded() -> Self {
        Self {
            state: SSEValidityState::ForwardOnly,
            ..Default::default()
        }
    }

    pub fn backward(
        state: SSEValidityState,
        not_valid_before: SSEValidityLocation,
        not_valid_after: SSEValidityLocation,
    ) -> Self {
        Self {
            state,
            not_valid_before,
            not_valid_after,
            locally_bounded: None,
        }
    }

    pub fn backward_unbounded() -> Self {
        Self {
            state: SSEValidityState::Both,
            not_valid_before: SSEValidityLocation::unbounded(),
            not_valid_after: SSEValidityLocation::unbounded(),
            locally_bounded: None,
        }
    }

    pub fn in_bounds(&self, loc: &Location) -> bool {
        self.not_valid_before.in_lower_bound(loc) && self.not_valid_after.in_upper_bound(loc)
    }

    pub fn has_local_bound(&self) -> bool {
        self.locally_bounded.is_some()
    }

    pub fn is_locally_bounded(&self, loc: &Location) -> bool {
        self.locally_bounded
            .map_or(false, |addr| loc.address() == addr)
    }

    pub fn is_forward_live(&self, loc: &Location) -> bool {
        self.state.is_forward_or_both()
            && (!self.has_local_bound() || self.is_locally_bounded(loc))
            && self.not_valid_before.in_lower_bound(loc)
            // && self.not_valid_after.in_upper_bound(loc)
    }

    pub fn is_backward_live(&self, loc: &Location) -> bool {
        self.state.is_backward_or_both()
            && (!self.has_local_bound() || self.is_locally_bounded(loc))
            // && self.not_valid_before.in_lower_bound(loc)
            && self.not_valid_after.in_upper_bound(loc)
    }

    pub fn is_forward_unbounded(&self) -> bool {
        !self.has_local_bound()
            && self.state.is_forward_or_both()
            && self.not_valid_after.is_unbounded()
    }

    pub fn is_backward_unbounded(&self) -> bool {
        !self.has_local_bound()
            && self.state.is_backward_or_both()
            && self.not_valid_before.is_unbounded()
    }

    pub fn is_backward_or_both(&self) -> bool {
        self.state.is_backward_or_both()
    }

    pub fn with_validity(mut self, other: &Self) -> Self {
        self.state = other.state;
        self.not_valid_before = other.not_valid_before;
        self.not_valid_after = other.not_valid_after;
        self.locally_bounded = other.locally_bounded;
        self
    }

    pub fn define(&mut self, loc: &Location) {
        self.not_valid_before = SSEValidityLocation::new(*loc);
    }

    pub fn kill(&mut self, loc: &Location) {
        self.not_valid_after = SSEValidityLocation::new(*loc);
    }

    pub fn bound_to(&mut self, addr: Address) {
        self.locally_bounded = Some(addr);
    }
}

#[derive(Debug, Clone, Default)]
pub struct SSEValiditySet<'a> {
    validities: AHashSet<SSEValidity>,
    sources: AHashSet<SSEValiditySource<'a>>,
}

impl<'a> SSEValiditySet<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.validities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validities.is_empty()
    }

    pub fn insert(&mut self, v: SSEValidity) -> bool {
        let before = self.validities.len();
        let inserted = self.validities.insert(v);
        if inserted && self.validities.len() > 4 {
            tracing::debug!(
                "validity set grew: {} -> {} (inserted: {})",
                before,
                self.validities.len(),
                v
            );
        }
        inserted
    }

    pub fn add_source(&mut self, s: SSEValiditySource<'a>) {
        self.sources.insert(s);
    }

    pub fn insert_with_source(&mut self, v: SSEValidity, s: SSEValiditySource<'a>) -> bool {
        self.sources.insert(s);
        self.validities.insert(v)
    }

    pub fn iter(&self) -> impl Iterator<Item = &SSEValidity> {
        self.validities.iter()
    }

    pub fn sources(&self) -> impl Iterator<Item = &SSEValiditySource<'a>> {
        self.sources.iter()
    }

    pub fn sources_mut(&mut self) -> &mut AHashSet<SSEValiditySource<'a>> {
        &mut self.sources
    }

    pub fn equivalent_validity(&self, other: &Self) -> bool {
        self.validities == other.validities
    }

    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.validities
            .iter()
            .all(|v| other.validities.iter().any(|ov| v.is_subset_of(ov)))
    }

    pub fn drain(&mut self) -> impl Iterator<Item = SSEValidity> + '_ {
        self.validities.drain()
    }

    pub fn drain_sources(&mut self) -> impl Iterator<Item = SSEValiditySource<'a>> + '_ {
        self.sources.drain()
    }

    pub fn clear(&mut self) {
        self.validities.clear();
        self.sources.clear();
    }

    pub fn extend_from(&mut self, other: &Self) {
        let before = self.validities.len();
        self.validities.extend(other.validities.iter().copied());
        self.sources.extend(other.sources.iter().cloned());
        if self.validities.len() > before && self.validities.len() > 4 {
            tracing::debug!(
                "validity set extended: {} -> {}",
                before,
                self.validities.len()
            );
        }
    }

    pub fn map_validities(&mut self, f: impl FnMut(SSEValidity) -> SSEValidity) {
        self.validities = self.validities.drain().map(f).collect();
    }
}

impl<'a> Extend<SSEValidity> for SSEValiditySet<'a> {
    fn extend<T: IntoIterator<Item = SSEValidity>>(&mut self, iter: T) {
        self.validities.extend(iter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity_subset_accepts_tighter_upper_bound() {
        let broad = SSEValidity::backward(
            SSEValidityState::Both,
            SSEValidityLocation::new(Location::new(Address::from(0x4eeb8u32), 1)),
            SSEValidityLocation::unbounded(),
        );
        let tight = SSEValidity::backward(
            SSEValidityState::Both,
            SSEValidityLocation::new(Location::new(Address::from(0x4eeb8u32), 1)),
            SSEValidityLocation::new(Location::new(Address::from(0x4eed0u32), 0)),
        );

        assert!(tight.is_subset_of(&broad));
        assert!(!broad.is_subset_of(&tight));
    }

    #[test]
    fn validity_set_subset_uses_semantic_inclusion() {
        let broad = SSEValidity::backward(
            SSEValidityState::Both,
            SSEValidityLocation::new(Location::new(Address::from(0x4eeb8u32), 1)),
            SSEValidityLocation::unbounded(),
        );
        let tight = SSEValidity::backward(
            SSEValidityState::Both,
            SSEValidityLocation::new(Location::new(Address::from(0x4eeb8u32), 1)),
            SSEValidityLocation::new(Location::new(Address::from(0x4eed0u32), 0)),
        );

        let mut lhs = SSEValiditySet::new();
        lhs.insert(tight);

        let mut rhs = SSEValiditySet::new();
        rhs.insert(broad);

        assert!(lhs.is_subset_of(&rhs));
        assert!(!rhs.is_subset_of(&lhs));
    }
}
