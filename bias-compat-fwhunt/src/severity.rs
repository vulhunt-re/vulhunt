use bias::pipeline::types::Severity;

use crate::meta::{Meta, CVSS};

fn cvss_severity_to_rule_severity(severity: &str) -> Option<Severity> {
    // NOTE: there is no consistency in capitalisation in the descriptions...
    match severity.to_lowercase().as_ref() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

fn cvss_to_rule_severity(cvss: &CVSS) -> Option<Severity> {
    let severity = cvss_severity_to_rule_severity(cvss.severity());

    if severity.is_some() {
        return severity;
    }

    if cvss.version().starts_with("4") {
        if let Some(v4) = cvss
            .score()
            .as_ref()
            .and_then(|val| val.parse::<f64>().ok())
        {
            return Some(if v4 >= 9.0 {
                Severity::Critical
            } else if v4 >= 7.0 {
                Severity::High
            } else if v4 >= 4.0 {
                Severity::Medium
            } else if v4 >= 0.1 {
                Severity::Low
            } else {
                Severity::None
            });
        }
    }

    if cvss.version().starts_with("3") {
        if let Some(v3) = cvss
            .score()
            .as_ref()
            .and_then(|val| val.parse::<f64>().ok())
        {
            return Some(if v3 >= 9.0 {
                Severity::Critical
            } else if v3 >= 7.0 {
                Severity::High
            } else if v3 >= 4.0 {
                Severity::Medium
            } else if v3 >= 0.1 {
                Severity::Low
            } else {
                Severity::None
            });
        }
    }

    if cvss.version().starts_with("2") {
        if let Some(v2) = cvss
            .score()
            .as_ref()
            .and_then(|val| val.parse::<f64>().ok())
        {
            return Some(if v2 >= 7.0 {
                Severity::High
            } else if v2 >= 4.0 {
                Severity::Medium
            } else {
                Severity::Low
            });
        }
    }

    None
}

pub(crate) fn meta_severity(meta: &Meta) -> Severity {
    if let Some(severity) = meta.cvss().as_ref().and_then(cvss_to_rule_severity) {
        severity
    } else {
        meta.namespace_severity()
    }
}
