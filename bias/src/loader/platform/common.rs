use std::collections::BTreeMap;

use crate::component::{
    ComponentIdentity, ComponentIdentityBuilder, HasComponentIdentity,
};
use crate::platform::PlatformProvider;
use ustr::UstrMap;
use uuid::Uuid;

#[derive(Default)]
pub struct PrimaryComponents {
    mapping: UstrMap<BTreeMap<ComponentIdentity, Uuid>>,
    builder: ComponentIdentityBuilder,
}

impl PrimaryComponents {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn compute_identity(&mut self, value: &impl HasComponentIdentity) -> ComponentIdentity {
        value.compute_identity_with(&mut self.builder)
    }

    pub fn insert_identity(
        &mut self,
        platform: &'static str,
        identity: ComponentIdentity,
        cid: Uuid,
    ) {
        self.mapping
            .entry(platform.into())
            .or_default()
            .insert(identity, cid);
    }

    pub fn get_or_insert<P: PlatformProvider>(
        &mut self,
        cid: Uuid,
        value: &impl HasComponentIdentity,
    ) -> Uuid {
        self.get_or_insert_full::<P>(cid, value).1
    }

    pub fn get_or_insert_full<P: PlatformProvider>(
        &mut self,
        cid: Uuid,
        value: &impl HasComponentIdentity,
    ) -> (ComponentIdentity, Uuid) {
        self.get_or_insert_with_full(cid, value, P::NAME)
    }

    pub fn get_or_insert_with(
        &mut self,
        cid: Uuid,
        value: &impl HasComponentIdentity,
        platform: &'static str,
    ) -> Uuid {
        self.get_or_insert_with_full(cid, value, platform).1
    }

    pub fn get_or_insert_with_full(
        &mut self,
        cid: Uuid,
        value: &impl HasComponentIdentity,
        platform: &'static str,
    ) -> (ComponentIdentity, Uuid) {
        let pid = value.compute_identity_with(&mut self.builder);
        (
            pid,
            *self
                .mapping
                .entry(platform.into())
                .or_default()
                .entry(pid)
                .or_insert(cid),
        )
    }
}
