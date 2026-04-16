use std::fmt::Display;

use crate::prelude::*;

use super::SSETrace;
use super::analysis::{BoundaryValidationPolicy, SSECallString};

macro_rules! report_violation {
    ($policy:expr, $($arg:tt)+) => {
        match $policy {
            BoundaryValidationPolicy::Warn => tracing::warn!($($arg)+),
            BoundaryValidationPolicy::Panic => panic!($($arg)+),
            BoundaryValidationPolicy::Off => return,
        }
    };
}

pub(crate) fn validate_sanity(
    policy: BoundaryValidationPolicy,
    source: &str,
    kind: &str,
    loc: impl Into<Option<Location>>,
    cs: &SSECallString,
    trace: &SSETrace<'_>,
) {
    let project = trace.project();
    let loc = loc.into();
    let loc = loc.as_ref().map_or(&"-" as &dyn Display, |l| l as &_);

    for tracked in trace.tracked_set() {
        if tracked.is_temporary() || tracked.generation() != 0 {
            report_violation!(
                policy,
                "{} returned non-canonical {} trace at {} for {}: tracked var {} is not in prototype space",
                source,
                kind,
                loc,
                cs,
                tracked.display(project)
            );
        }
    }

    for (var, sses) in trace.sses() {
        if var.is_temporary() || var.generation() != 0 {
            report_violation!(
                policy,
                "{} returned non-canonical {} trace at {} for {}: key {} is not in prototype space",
                source,
                kind,
                loc,
                cs,
                var.display(project)
            );
        }

        for (sse, validity) in sses {
            if validity.is_empty() {
                report_violation!(
                    policy,
                    "{} returned invalid {} trace at {} for {}: {} -> {} has no validity",
                    source,
                    kind,
                    loc,
                    cs,
                    var.display(project),
                    sse.display(project)
                );
            }
        }
    }
}

pub(crate) fn validate_validity_preservation(
    policy: BoundaryValidationPolicy,
    source: &str,
    kind: &str,
    loc: impl Into<Option<Location>>,
    cs: &SSECallString,
    old_trace: &SSETrace<'_>,
    new_trace: &SSETrace<'_>,
) {
    let loc = loc.into();
    let loc = loc.as_ref().map_or(&"-" as &dyn Display, |l| l as &_);

    let project = old_trace.project();

    for (var, old_sses) in old_trace.sses() {
        let Some(new_sses) = new_trace.sses().get(var) else {
            continue;
        };

        for (sse, old_validity) in old_sses {
            let Some(new_validity) = new_sses.get(sse) else {
                continue;
            };

            if !old_validity.is_subset_of(new_validity) {
                report_violation!(
                    policy,
                    "{} contracted validity on {} trace at {} for {}: {} -> {}",
                    source,
                    kind,
                    loc,
                    cs,
                    var.display(project),
                    sse.display(project)
                );
            }
        }
    }
}

pub(crate) fn validate_widening_sanity(
    policy: BoundaryValidationPolicy,
    loc: impl Into<Option<Location>>,
    cs: &SSECallString,
    trace: &SSETrace<'_>,
) {
    validate_sanity(policy, "widening operator", "block", loc, cs, trace);
}

pub(crate) fn validate_monotonicity(
    policy: BoundaryValidationPolicy,
    source: &str,
    kind: &str,
    loc: impl Into<Option<Location>>,
    cs: &SSECallString,
    old_trace: &SSETrace<'_>,
    new_trace: &SSETrace<'_>,
) {
    let loc = loc.into();
    let loc = loc.as_ref().map_or(&"-" as &dyn Display, |l| l as &_);

    if !old_trace.validity_is_subset_of(new_trace.sses()) {
        report_violation!(
            policy,
            "{} produced non-monotonic {} trace change at {} for {}",
            source,
            kind,
            loc,
            cs
        );
    }
}

pub(crate) fn validate_handler_monotonicity(
    policy: BoundaryValidationPolicy,
    kind: &str,
    loc: Location,
    cs: &SSECallString,
    old_trace: &SSETrace<'_>,
    new_trace: &SSETrace<'_>,
) {
    validate_monotonicity(policy, "handler", kind, loc, cs, old_trace, new_trace);
}

pub(crate) fn validate_consistency(
    policy: BoundaryValidationPolicy,
    source: &str,
    kind: &str,
    loc: impl Into<Option<Location>>,
    cs: &SSECallString,
    old_trace: &SSETrace<'_>,
    new_trace: &SSETrace<'_>,
) {
    let loc = loc.into();
    validate_sanity(policy, source, kind, loc, cs, new_trace);
    validate_validity_preservation(policy, source, kind, loc, cs, old_trace, new_trace);
}

pub(crate) fn validate_handler_consistency(
    policy: BoundaryValidationPolicy,
    kind: &str,
    loc: Location,
    cs: &SSECallString,
    old_trace: &SSETrace<'_>,
    new_trace: &SSETrace<'_>,
) {
    validate_consistency(policy, "handler", kind, loc, cs, old_trace, new_trace);
}

pub(crate) fn validate_widening(
    policy: BoundaryValidationPolicy,
    loc: impl Into<Option<Location>>,
    cs: &SSECallString,
    old_trace: &SSETrace<'_>,
    new_trace: &SSETrace<'_>,
) {
    let loc = loc.into();
    validate_consistency(
        policy,
        "widening operator",
        "block",
        loc,
        cs,
        old_trace,
        new_trace,
    );
    validate_monotonicity(
        policy,
        "widening operator",
        "block",
        loc,
        cs,
        old_trace,
        new_trace,
    );
}
