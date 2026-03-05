use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const OB0001: &'static str = "OB0001: Anti-Behavioral Analysis";
pub const OB0002: &'static str = "OB0002: Anti-Static Analysis";
pub const OB0003: &'static str = "OB0003: Collection";
pub const OB0004: &'static str = "OB0004: Command and Control";
pub const OB0005: &'static str = "OB0005: Credential Access";
pub const OB0006: &'static str = "OB0006: Defense Evasion";
pub const OB0007: &'static str = "OB0007: Discovery";
pub const OB0009: &'static str = "OB0009: Execution";
pub const OB0010: &'static str = "OB0010: Exfiltration";
pub const OB0008: &'static str = "OB0008: Impact";
pub const OB0011: &'static str = "OB0011: Lateral Movement";
pub const OB0012: &'static str = "OB0012: Persistence";
pub const OB0013: &'static str = "OB0013: Privilege Escalation";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum MalwareObjectives {
    #[serde(rename = "OB0001", alias = "OB0001: Anti-Behavioral Analysis")]
    OB0001,
    #[serde(rename = "OB0002", alias = "OB0002: Anti-Static Analysis")]
    OB0002,
    #[serde(rename = "OB0003", alias = "OB0003: Collection")]
    OB0003,
    #[serde(rename = "OB0004", alias = "OB0004: Command and Control")]
    OB0004,
    #[serde(rename = "OB0005", alias = "OB0005: Credential Access")]
    OB0005,
    #[serde(rename = "OB0006", alias = "OB0006: Defense Evasion")]
    OB0006,
    #[serde(rename = "OB0007", alias = "OB0007: Discovery")]
    OB0007,
    #[serde(rename = "OB0009", alias = "OB0009: Execution")]
    OB0009,
    #[serde(rename = "OB0010", alias = "OB0010: Exfiltration")]
    OB0010,
    #[serde(rename = "OB0008", alias = "OB0008: Impact")]
    OB0008,
    #[serde(rename = "OB0011", alias = "OB0011: Lateral Movement")]
    OB0011,
    #[serde(rename = "OB0012", alias = "OB0012: Persistence")]
    OB0012,
    #[serde(rename = "OB0013", alias = "OB0013: Privilege Escalation")]
    OB0013,
}

impl std::fmt::Display for MalwareObjectives {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            MalwareObjectives::OB0001 => OB0001,
            MalwareObjectives::OB0002 => OB0002,
            MalwareObjectives::OB0003 => OB0003,
            MalwareObjectives::OB0004 => OB0004,
            MalwareObjectives::OB0005 => OB0005,
            MalwareObjectives::OB0006 => OB0006,
            MalwareObjectives::OB0007 => OB0007,
            MalwareObjectives::OB0009 => OB0009,
            MalwareObjectives::OB0010 => OB0010,
            MalwareObjectives::OB0008 => OB0008,
            MalwareObjectives::OB0011 => OB0011,
            MalwareObjectives::OB0012 => OB0012,
            MalwareObjectives::OB0013 => OB0013,
        };
        f.write_str(description)
    }
}

#[derive(Debug, Error)]
#[error("failed to parse malware objective")]
pub struct MalwareObjectiveError;

impl std::str::FromStr for MalwareObjectives {
    type Err = MalwareObjectiveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "OB0001" | OB0001 => Ok(MalwareObjectives::OB0001),
            "OB0002" | OB0002 => Ok(MalwareObjectives::OB0002),
            "OB0003" | OB0003 => Ok(MalwareObjectives::OB0003),
            "OB0004" | OB0004 => Ok(MalwareObjectives::OB0004),
            "OB0005" | OB0005 => Ok(MalwareObjectives::OB0005),
            "OB0006" | OB0006 => Ok(MalwareObjectives::OB0006),
            "OB0007" | OB0007 => Ok(MalwareObjectives::OB0007),
            "OB0009" | OB0009 => Ok(MalwareObjectives::OB0009),
            "OB0010" | OB0010 => Ok(MalwareObjectives::OB0010),
            "OB0008" | OB0008 => Ok(MalwareObjectives::OB0008),
            "OB0011" | OB0011 => Ok(MalwareObjectives::OB0011),
            "OB0012" | OB0012 => Ok(MalwareObjectives::OB0012),
            "OB0013" | OB0013 => Ok(MalwareObjectives::OB0013),
            _ => Err(MalwareObjectiveError),
        }
    }
}

impl MalwareObjectives {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OB0001 => OB0001,
            Self::OB0002 => OB0002,
            Self::OB0003 => OB0003,
            Self::OB0004 => OB0004,
            Self::OB0005 => OB0005,
            Self::OB0006 => OB0006,
            Self::OB0007 => OB0007,
            Self::OB0009 => OB0009,
            Self::OB0010 => OB0010,
            Self::OB0008 => OB0008,
            Self::OB0011 => OB0011,
            Self::OB0012 => OB0012,
            Self::OB0013 => OB0013,
        }
    }
}

pub const OC0006: &'static str = "OC0006: Communication";
pub const OC0005: &'static str = "OC0005: Cryptography";
pub const OC0004: &'static str = "OC0004: Data";
pub const OC0001: &'static str = "OC0001: File System";
pub const OC0007: &'static str = "OC0007: Hardware";
pub const OC0002: &'static str = "OC0002: Memory";
pub const OC0008: &'static str = "OC0008: Operating System";
pub const OC0003: &'static str = "OC0003: Process";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum MalwareMicroObjectives {
    #[serde(rename = "OC0006", alias = "OC0006: Communication")]
    OC0006,
    #[serde(rename = "OC0005", alias = "OC0005: Cryptography")]
    OC0005,
    #[serde(rename = "OC0004", alias = "OC0004: Data")]
    OC0004,
    #[serde(rename = "OC0001", alias = "OC0001: File System")]
    OC0001,
    #[serde(rename = "OC0007", alias = "OC0007: Hardware")]
    OC0007,
    #[serde(rename = "OC0002", alias = "OC0002: Memory")]
    OC0002,
    #[serde(rename = "OC0008", alias = "OC0008: Operating System")]
    OC0008,
    #[serde(rename = "OC0003", alias = "OC0003: Process")]
    OC0003,
}

impl std::fmt::Display for MalwareMicroObjectives {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            MalwareMicroObjectives::OC0006 => OC0006,
            MalwareMicroObjectives::OC0005 => OC0005,
            MalwareMicroObjectives::OC0004 => OC0004,
            MalwareMicroObjectives::OC0001 => OC0001,
            MalwareMicroObjectives::OC0007 => OC0007,
            MalwareMicroObjectives::OC0002 => OC0002,
            MalwareMicroObjectives::OC0008 => OC0008,
            MalwareMicroObjectives::OC0003 => OC0003,
        };
        f.write_str(description)
    }
}

#[derive(Debug, Error)]
#[error("failed to parse malware micro-objective")]
pub struct MalwareMicroObjectiveError;

impl std::str::FromStr for MalwareMicroObjectives {
    type Err = MalwareMicroObjectiveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "OC0006" | OC0006 => Ok(MalwareMicroObjectives::OC0006),
            "OC0005" | OC0005 => Ok(MalwareMicroObjectives::OC0005),
            "OC0004" | OC0004 => Ok(MalwareMicroObjectives::OC0004),
            "OC0001" | OC0001 => Ok(MalwareMicroObjectives::OC0001),
            "OC0007" | OC0007 => Ok(MalwareMicroObjectives::OC0007),
            "OC0002" | OC0002 => Ok(MalwareMicroObjectives::OC0002),
            "OC0008" | OC0008 => Ok(MalwareMicroObjectives::OC0008),
            "OC0003" | OC0003 => Ok(MalwareMicroObjectives::OC0003),
            _ => Err(MalwareMicroObjectiveError),
        }
    }
}

impl MalwareMicroObjectives {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OC0006 => OC0006,
            Self::OC0005 => OC0005,
            Self::OC0004 => OC0004,
            Self::OC0001 => OC0001,
            Self::OC0007 => OC0007,
            Self::OC0002 => OC0002,
            Self::OC0008 => OC0008,
            Self::OC0003 => OC0003,
        }
    }
}

pub const B0010: &'static str = "B0010: Call Graph Generation Evasion";
pub const B0032: &'static str = "B0032: Executable Code Obfuscation";
pub const B0034: &'static str = "B0034: Executable Code Optimization";
pub const B0008: &'static str = "B0008: Executable Code Virtualization";
pub const B0045: &'static str = "B0045: Data Flow Analysis Evasion";
pub const B0012: &'static str = "B0012: Disassembler Evasion";
pub const B0014: &'static str = "B0014: SMTP Connection Discovery";
pub const B0046: &'static str = "B0046: Code Discovery";
pub const B0038: &'static str = "B0038: Self Discovery";
pub const B0013: &'static str = "B0013: Analysis Tool Discovery";
pub const B0043: &'static str = "B0043: Taskbar Discovery";
pub const B0028: &'static str = "B0028: Cryptocurrency";
pub const B0030: &'static str = "B0030: C2 Communication";
pub const B0031: &'static str = "B0031: Domain Name Generation";
pub const B0024: &'static str = "B0024: Prevent Concurrent Execution";
pub const B0044: &'static str = "B0044: Execution Dependency";
pub const B0023: &'static str = "B0023: Install Additional Program";
pub const B0020: &'static str = "B0020: Send Email";
pub const B0011: &'static str = "B0011: Remote Commands";
pub const B0025: &'static str = "B0025: Conditional Execution";
pub const B0021: &'static str = "B0021: Send Poisoned Text Message";
pub const B0026: &'static str = "B0026: Malicious Network Driver";
pub const B0035: &'static str = "B0035: Shutdown Event";
pub const B0018: &'static str = "B0018: Resource Hijacking";
pub const B0022: &'static str = "B0022: Remote Access";
pub const B0017: &'static str = "B0017: Destroy Hardware";
pub const B0016: &'static str = "B0016: Compromise Data Integrity";
pub const B0033: &'static str = "B0033: Denial of Service";
pub const B0019: &'static str = "B0019: Manipulate Network Traffic";
pub const B0042: &'static str = "B0042: Modify Hardware";
pub const B0039: &'static str = "B0039: Spamming";
pub const B0006: &'static str = "B0006: Memory Dump Evasion";
pub const B0036: &'static str = "B0036: Capture Evasion";
pub const B0009: &'static str = "B0009: Virtual Machine Detection";
pub const B0007: &'static str = "B0007: Sandbox Detection";
pub const B0005: &'static str = "B0005: Emulator Evasion";
pub const B0002: &'static str = "B0002: Debugger Evasion";
pub const B0001: &'static str = "B0001: Debugger Detection";
pub const B0004: &'static str = "B0004: Emulator Detection";
pub const B0003: &'static str = "B0003: Dynamic Analysis Evasion";
pub const B0037: &'static str = "B0037: Bypass Data Execution Prevention";
pub const B0047: &'static str = "B0047: Install Insecure or Malicious Configuration";
pub const B0040: &'static str = "B0040: Covert Location";
pub const B0029: &'static str = "B0029: Polymorphic Code";
pub const B0027: &'static str = "B0027: Alternative Installation Location";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum MalwareBehaviours {
    #[serde(rename = "B0010", alias = "B0010: Call Graph Generation Evasion")]
    B0010,
    #[serde(rename = "B0032", alias = "B0032: Executable Code Obfuscation")]
    B0032,
    #[serde(rename = "B0034", alias = "B0034: Executable Code Optimization")]
    B0034,
    #[serde(rename = "B0008", alias = "B0008: Executable Code Virtualization")]
    B0008,
    #[serde(rename = "B0045", alias = "B0045: Data Flow Analysis Evasion")]
    B0045,
    #[serde(rename = "B0012", alias = "B0012: Disassembler Evasion")]
    B0012,
    #[serde(rename = "B0014", alias = "B0014: SMTP Connection Discovery")]
    B0014,
    #[serde(rename = "B0046", alias = "B0046: Code Discovery")]
    B0046,
    #[serde(rename = "B0038", alias = "B0038: Self Discovery")]
    B0038,
    #[serde(rename = "B0013", alias = "B0013: Analysis Tool Discovery")]
    B0013,
    #[serde(rename = "B0043", alias = "B0043: Taskbar Discovery")]
    B0043,
    #[serde(rename = "B0028", alias = "B0028: Cryptocurrency")]
    B0028,
    #[serde(rename = "B0030", alias = "B0030: C2 Communication")]
    B0030,
    #[serde(rename = "B0031", alias = "B0031: Domain Name Generation")]
    B0031,
    #[serde(rename = "B0024", alias = "B0024: Prevent Concurrent Execution")]
    B0024,
    #[serde(rename = "B0044", alias = "B0044: Execution Dependency")]
    B0044,
    #[serde(rename = "B0023", alias = "B0023: Install Additional Program")]
    B0023,
    #[serde(rename = "B0020", alias = "B0020: Send Email")]
    B0020,
    #[serde(rename = "B0011", alias = "B0011: Remote Commands")]
    B0011,
    #[serde(rename = "B0025", alias = "B0025: Conditional Execution")]
    B0025,
    #[serde(rename = "B0021", alias = "B0021: Send Poisoned Text Message")]
    B0021,
    #[serde(rename = "B0026", alias = "B0026: Malicious Network Driver")]
    B0026,
    #[serde(rename = "B0035", alias = "B0035: Shutdown Event")]
    B0035,
    #[serde(rename = "B0018", alias = "B0018: Resource Hijacking")]
    B0018,
    #[serde(rename = "B0022", alias = "B0022: Remote Access")]
    B0022,
    #[serde(rename = "B0017", alias = "B0017: Destroy Hardware")]
    B0017,
    #[serde(rename = "B0016", alias = "B0016: Compromise Data Integrity")]
    B0016,
    #[serde(rename = "B0033", alias = "B0033: Denial of Service")]
    B0033,
    #[serde(rename = "B0019", alias = "B0019: Manipulate Network Traffic")]
    B0019,
    #[serde(rename = "B0042", alias = "B0042: Modify Hardware")]
    B0042,
    #[serde(rename = "B0039", alias = "B0039: Spamming")]
    B0039,
    #[serde(rename = "B0006", alias = "B0006: Memory Dump Evasion")]
    B0006,
    #[serde(rename = "B0036", alias = "B0036: Capture Evasion")]
    B0036,
    #[serde(rename = "B0009", alias = "B0009: Virtual Machine Detection")]
    B0009,
    #[serde(rename = "B0007", alias = "B0007: Sandbox Detection")]
    B0007,
    #[serde(rename = "B0005", alias = "B0005: Emulator Evasion")]
    B0005,
    #[serde(rename = "B0002", alias = "B0002: Debugger Evasion")]
    B0002,
    #[serde(rename = "B0001", alias = "B0001: Debugger Detection")]
    B0001,
    #[serde(rename = "B0004", alias = "B0004: Emulator Detection")]
    B0004,
    #[serde(rename = "B0003", alias = "B0003: Dynamic Analysis Evasion")]
    B0003,
    #[serde(rename = "B0037", alias = "B0037: Bypass Data Execution Prevention")]
    B0037,
    #[serde(
        rename = "B0047",
        alias = "B0047: Install Insecure or Malicious Configuration"
    )]
    B0047,
    #[serde(rename = "B0040", alias = "B0040: Covert Location")]
    B0040,
    #[serde(rename = "B0029", alias = "B0029: Polymorphic Code")]
    B0029,
    #[serde(rename = "B0027", alias = "B0027: Alternative Installation Location")]
    B0027,
}

impl std::fmt::Display for MalwareBehaviours {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            MalwareBehaviours::B0010 => B0010,
            MalwareBehaviours::B0032 => B0032,
            MalwareBehaviours::B0034 => B0034,
            MalwareBehaviours::B0008 => B0008,
            MalwareBehaviours::B0045 => B0045,
            MalwareBehaviours::B0012 => B0012,
            MalwareBehaviours::B0014 => B0014,
            MalwareBehaviours::B0046 => B0046,
            MalwareBehaviours::B0038 => B0038,
            MalwareBehaviours::B0013 => B0013,
            MalwareBehaviours::B0043 => B0043,
            MalwareBehaviours::B0028 => B0028,
            MalwareBehaviours::B0030 => B0030,
            MalwareBehaviours::B0031 => B0031,
            MalwareBehaviours::B0024 => B0024,
            MalwareBehaviours::B0044 => B0044,
            MalwareBehaviours::B0023 => B0023,
            MalwareBehaviours::B0020 => B0020,
            MalwareBehaviours::B0011 => B0011,
            MalwareBehaviours::B0025 => B0025,
            MalwareBehaviours::B0021 => B0021,
            MalwareBehaviours::B0026 => B0026,
            MalwareBehaviours::B0035 => B0035,
            MalwareBehaviours::B0018 => B0018,
            MalwareBehaviours::B0022 => B0022,
            MalwareBehaviours::B0017 => B0017,
            MalwareBehaviours::B0016 => B0016,
            MalwareBehaviours::B0033 => B0033,
            MalwareBehaviours::B0019 => B0019,
            MalwareBehaviours::B0042 => B0042,
            MalwareBehaviours::B0039 => B0039,
            MalwareBehaviours::B0006 => B0006,
            MalwareBehaviours::B0036 => B0036,
            MalwareBehaviours::B0009 => B0009,
            MalwareBehaviours::B0007 => B0007,
            MalwareBehaviours::B0005 => B0005,
            MalwareBehaviours::B0002 => B0002,
            MalwareBehaviours::B0001 => B0001,
            MalwareBehaviours::B0004 => B0004,
            MalwareBehaviours::B0003 => B0003,
            MalwareBehaviours::B0037 => B0037,
            MalwareBehaviours::B0047 => B0047,
            MalwareBehaviours::B0040 => B0040,
            MalwareBehaviours::B0029 => B0029,
            MalwareBehaviours::B0027 => B0027,
        };
        f.write_str(description)
    }
}

#[derive(Debug, Error)]
#[error("failed to parse malware behaviour")]
pub struct MalwareBehaviourError;

impl std::str::FromStr for MalwareBehaviours {
    type Err = MalwareBehaviourError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "B0010" | B0010 => Ok(MalwareBehaviours::B0010),
            "B0032" | B0032 => Ok(MalwareBehaviours::B0032),
            "B0034" | B0034 => Ok(MalwareBehaviours::B0034),
            "B0008" | B0008 => Ok(MalwareBehaviours::B0008),
            "B0045" | B0045 => Ok(MalwareBehaviours::B0045),
            "B0012" | B0012 => Ok(MalwareBehaviours::B0012),
            "B0014" | B0014 => Ok(MalwareBehaviours::B0014),
            "B0046" | B0046 => Ok(MalwareBehaviours::B0046),
            "B0038" | B0038 => Ok(MalwareBehaviours::B0038),
            "B0013" | B0013 => Ok(MalwareBehaviours::B0013),
            "B0043" | B0043 => Ok(MalwareBehaviours::B0043),
            "B0028" | B0028 => Ok(MalwareBehaviours::B0028),
            "B0030" | B0030 => Ok(MalwareBehaviours::B0030),
            "B0031" | B0031 => Ok(MalwareBehaviours::B0031),
            "B0024" | B0024 => Ok(MalwareBehaviours::B0024),
            "B0044" | B0044 => Ok(MalwareBehaviours::B0044),
            "B0023" | B0023 => Ok(MalwareBehaviours::B0023),
            "B0020" | B0020 => Ok(MalwareBehaviours::B0020),
            "B0011" | B0011 => Ok(MalwareBehaviours::B0011),
            "B0025" | B0025 => Ok(MalwareBehaviours::B0025),
            "B0021" | B0021 => Ok(MalwareBehaviours::B0021),
            "B0026" | B0026 => Ok(MalwareBehaviours::B0026),
            "B0035" | B0035 => Ok(MalwareBehaviours::B0035),
            "B0018" | B0018 => Ok(MalwareBehaviours::B0018),
            "B0022" | B0022 => Ok(MalwareBehaviours::B0022),
            "B0017" | B0017 => Ok(MalwareBehaviours::B0017),
            "B0016" | B0016 => Ok(MalwareBehaviours::B0016),
            "B0033" | B0033 => Ok(MalwareBehaviours::B0033),
            "B0019" | B0019 => Ok(MalwareBehaviours::B0019),
            "B0042" | B0042 => Ok(MalwareBehaviours::B0042),
            "B0039" | B0039 => Ok(MalwareBehaviours::B0039),
            "B0006" | B0006 => Ok(MalwareBehaviours::B0006),
            "B0036" | B0036 => Ok(MalwareBehaviours::B0036),
            "B0009" | B0009 => Ok(MalwareBehaviours::B0009),
            "B0007" | B0007 => Ok(MalwareBehaviours::B0007),
            "B0005" | B0005 => Ok(MalwareBehaviours::B0005),
            "B0002" | B0002 => Ok(MalwareBehaviours::B0002),
            "B0001" | B0001 => Ok(MalwareBehaviours::B0001),
            "B0004" | B0004 => Ok(MalwareBehaviours::B0004),
            "B0003" | B0003 => Ok(MalwareBehaviours::B0003),
            "B0037" | B0037 => Ok(MalwareBehaviours::B0037),
            "B0047" | B0047 => Ok(MalwareBehaviours::B0047),
            "B0040" | B0040 => Ok(MalwareBehaviours::B0040),
            "B0029" | B0029 => Ok(MalwareBehaviours::B0029),
            "B0027" | B0027 => Ok(MalwareBehaviours::B0027),
            _ => Err(MalwareBehaviourError),
        }
    }
}

impl MalwareBehaviours {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::B0010 => B0010,
            Self::B0032 => B0032,
            Self::B0034 => B0034,
            Self::B0008 => B0008,
            Self::B0045 => B0045,
            Self::B0012 => B0012,
            Self::B0014 => B0014,
            Self::B0046 => B0046,
            Self::B0038 => B0038,
            Self::B0013 => B0013,
            Self::B0043 => B0043,
            Self::B0028 => B0028,
            Self::B0030 => B0030,
            Self::B0031 => B0031,
            Self::B0024 => B0024,
            Self::B0044 => B0044,
            Self::B0023 => B0023,
            Self::B0020 => B0020,
            Self::B0011 => B0011,
            Self::B0025 => B0025,
            Self::B0021 => B0021,
            Self::B0026 => B0026,
            Self::B0035 => B0035,
            Self::B0018 => B0018,
            Self::B0022 => B0022,
            Self::B0017 => B0017,
            Self::B0016 => B0016,
            Self::B0033 => B0033,
            Self::B0019 => B0019,
            Self::B0042 => B0042,
            Self::B0039 => B0039,
            Self::B0006 => B0006,
            Self::B0036 => B0036,
            Self::B0009 => B0009,
            Self::B0007 => B0007,
            Self::B0005 => B0005,
            Self::B0002 => B0002,
            Self::B0001 => B0001,
            Self::B0004 => B0004,
            Self::B0003 => B0003,
            Self::B0037 => B0037,
            Self::B0047 => B0047,
            Self::B0040 => B0040,
            Self::B0029 => B0029,
            Self::B0027 => B0027,
        }
    }
}

pub const C0007: &'static str = "C0007: Allocate Memory";
pub const C0040: &'static str = "C0040: Allocate Thread Local Storage";
pub const C0015: &'static str = "C0015: Alter File Extension";
pub const C0008: &'static str = "C0008: Change Memory Protection";
pub const C0043: &'static str = "C0043: Check Mutex";
pub const C0019: &'static str = "C0019: Check String";
pub const C0032: &'static str = "C0032: Checksum";
pub const C0024: &'static str = "C0024: Compress Data";
pub const C0060: &'static str = "C0060: Compression Library";
pub const C0033: &'static str = "C0033: Console";
pub const C0045: &'static str = "C0045: Copy File";
pub const C0046: &'static str = "C0046: Create Directory";
pub const C0016: &'static str = "C0016: Create File";
pub const C0042: &'static str = "C0042: Create Mutex";
pub const C0017: &'static str = "C0017: Create Process";
pub const C0038: &'static str = "C0038: Create Thread";
pub const C0068: &'static str = "C0068: Crypto Algorithm";
pub const C0069: &'static str = "C0069: Crypto Constant";
pub const C0059: &'static str = "C0059: Crypto Library";
pub const C0029: &'static str = "C0029: Cryptographic Hash";
pub const C0011: &'static str = "C0011: DNS Communication";
pub const C0053: &'static str = "C0053: Decode Data";
pub const C0025: &'static str = "C0025: Decompress Data";
pub const C0031: &'static str = "C0031: Decrypt Data";
pub const C0048: &'static str = "C0048: Delete Directory";
pub const C0047: &'static str = "C0047: Delete File";
pub const C0026: &'static str = "C0026: Encode Data";
pub const C0027: &'static str = "C0027: Encrypt Data";
pub const C0028: &'static str = "C0028: Encryption Key";
pub const C0064: &'static str = "C0064: Enumerate Threads";
pub const C0034: &'static str = "C0034: Environment Variable";
pub const C0004: &'static str = "C0004: FTP Communication";
pub const C0044: &'static str = "C0044: Free Memory";
pub const C0021: &'static str = "C0021: Generate Pseudo-random Sequence";
pub const C0049: &'static str = "C0049: Get File Attributes";
pub const C0002: &'static str = "C0002: HTTP Communication";
pub const C0061: &'static str = "C0061: Hashed Message Authentication Code";
pub const C0006: &'static str = "C0006: Heap Spray";
pub const C0014: &'static str = "C0014: ICMP Communication";
pub const C0037: &'static str = "C0037: Install Driver";
pub const C0003: &'static str = "C0003: Interprocess Communication";
pub const C0023: &'static str = "C0023: Load Driver";
pub const C0058: &'static str = "C0058: Modulo";
pub const C0063: &'static str = "C0063: Move File";
pub const C0030: &'static str = "C0030: Non-Cryptographic Hash";
pub const C0065: &'static str = "C0065: Open Process";
pub const C0066: &'static str = "C0066: Open Thread";
pub const C0010: &'static str = "C0010: Overflow Buffer";
pub const C0051: &'static str = "C0051: Read File";
pub const C0056: &'static str = "C0056: Read Virtual Disk";
pub const C0036: &'static str = "C0036: Registry";
pub const C0054: &'static str = "C0054: Resume Thread";
pub const C0012: &'static str = "C0012: SMTP Communication";
pub const C0050: &'static str = "C0050: Set File Attributes";
pub const C0072: &'static str = "C0072: Set Thread Context";
pub const C0041: &'static str = "C0041: Set Thread Local Storage Value";
pub const C0057: &'static str = "C0057: Simulate Hardware";
pub const C0001: &'static str = "C0001: Socket Communication";
pub const C0009: &'static str = "C0009: Stack Pivot";
pub const C0055: &'static str = "C0055: Suspend Thread";
pub const C0018: &'static str = "C0018: Terminate Process";
pub const C0039: &'static str = "C0039: Terminate Thread";
pub const C0070: &'static str = "C0070: Unmap Section View";
pub const C0020: &'static str = "C0020: Use Constant";
pub const C0035: &'static str = "C0035: Wallpaper";
pub const C0005: &'static str = "C0005: WinINet";
pub const C0071: &'static str = "C0071: Write Process Memory";
pub const C0052: &'static str = "C0052: Writes File";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum MalwareMicroBehaviours {
    #[serde(rename = "C0007", alias = "C0007: Allocate Memory")]
    C0007,
    #[serde(rename = "C0040", alias = "C0040: Allocate Thread Local Storage")]
    C0040,
    #[serde(rename = "C0015", alias = "C0015: Alter File Extension")]
    C0015,
    #[serde(rename = "C0008", alias = "C0008: Change Memory Protection")]
    C0008,
    #[serde(rename = "C0043", alias = "C0043: Check Mutex")]
    C0043,
    #[serde(rename = "C0019", alias = "C0019: Check String")]
    C0019,
    #[serde(rename = "C0032", alias = "C0032: Checksum")]
    C0032,
    #[serde(rename = "C0024", alias = "C0024: Compress Data")]
    C0024,
    #[serde(rename = "C0060", alias = "C0060: Compression Library")]
    C0060,
    #[serde(rename = "C0033", alias = "C0033: Console")]
    C0033,
    #[serde(rename = "C0045", alias = "C0045: Copy File")]
    C0045,
    #[serde(rename = "C0046", alias = "C0046: Create Directory")]
    C0046,
    #[serde(rename = "C0016", alias = "C0016: Create File")]
    C0016,
    #[serde(rename = "C0042", alias = "C0042: Create Mutex")]
    C0042,
    #[serde(rename = "C0017", alias = "C0017: Create Process")]
    C0017,
    #[serde(rename = "C0038", alias = "C0038: Create Thread")]
    C0038,
    #[serde(rename = "C0068", alias = "C0068: Crypto Algorithm")]
    C0068,
    #[serde(rename = "C0069", alias = "C0069: Crypto Constant")]
    C0069,
    #[serde(rename = "C0059", alias = "C0059: Crypto Library")]
    C0059,
    #[serde(rename = "C0029", alias = "C0029: Cryptographic Hash")]
    C0029,
    #[serde(rename = "C0011", alias = "C0011: DNS Communication")]
    C0011,
    #[serde(rename = "C0053", alias = "C0053: Decode Data")]
    C0053,
    #[serde(rename = "C0025", alias = "C0025: Decompress Data")]
    C0025,
    #[serde(rename = "C0031", alias = "C0031: Decrypt Data")]
    C0031,
    #[serde(rename = "C0048", alias = "C0048: Delete Directory")]
    C0048,
    #[serde(rename = "C0047", alias = "C0047: Delete File")]
    C0047,
    #[serde(rename = "C0026", alias = "C0026: Encode Data")]
    C0026,
    #[serde(rename = "C0027", alias = "C0027: Encrypt Data")]
    C0027,
    #[serde(rename = "C0028", alias = "C0028: Encryption Key")]
    C0028,
    #[serde(rename = "C0064", alias = "C0064: Enumerate Threads")]
    C0064,
    #[serde(rename = "C0034", alias = "C0034: Environment Variable")]
    C0034,
    #[serde(rename = "C0004", alias = "C0004: FTP Communication")]
    C0004,
    #[serde(rename = "C0044", alias = "C0044: Free Memory")]
    C0044,
    #[serde(rename = "C0021", alias = "C0021: Generate Pseudo-random Sequence")]
    C0021,
    #[serde(rename = "C0049", alias = "C0049: Get File Attributes")]
    C0049,
    #[serde(rename = "C0002", alias = "C0002: HTTP Communication")]
    C0002,
    #[serde(rename = "C0061", alias = "C0061: Hashed Message Authentication Code")]
    C0061,
    #[serde(rename = "C0006", alias = "C0006: Heap Spray")]
    C0006,
    #[serde(rename = "C0014", alias = "C0014: ICMP Communication")]
    C0014,
    #[serde(rename = "C0037", alias = "C0037: Install Driver")]
    C0037,
    #[serde(rename = "C0003", alias = "C0003: Interprocess Communication")]
    C0003,
    #[serde(rename = "C0023", alias = "C0023: Load Driver")]
    C0023,
    #[serde(rename = "C0058", alias = "C0058: Modulo")]
    C0058,
    #[serde(rename = "C0063", alias = "C0063: Move File")]
    C0063,
    #[serde(rename = "C0030", alias = "C0030: Non-Cryptographic Hash")]
    C0030,
    #[serde(rename = "C0065", alias = "C0065: Open Process")]
    C0065,
    #[serde(rename = "C0066", alias = "C0066: Open Thread")]
    C0066,
    #[serde(rename = "C0010", alias = "C0010: Overflow Buffer")]
    C0010,
    #[serde(rename = "C0051", alias = "C0051: Read File")]
    C0051,
    #[serde(rename = "C0056", alias = "C0056: Read Virtual Disk")]
    C0056,
    #[serde(rename = "C0036", alias = "C0036: Registry")]
    C0036,
    #[serde(rename = "C0054", alias = "C0054: Resume Thread")]
    C0054,
    #[serde(rename = "C0012", alias = "C0012: SMTP Communication")]
    C0012,
    #[serde(rename = "C0050", alias = "C0050: Set File Attributes")]
    C0050,
    #[serde(rename = "C0072", alias = "C0072: Set Thread Context")]
    C0072,
    #[serde(rename = "C0041", alias = "C0041: Set Thread Local Storage Value")]
    C0041,
    #[serde(rename = "C0057", alias = "C0057: Simulate Hardware")]
    C0057,
    #[serde(rename = "C0001", alias = "C0001: Socket Communication")]
    C0001,
    #[serde(rename = "C0009", alias = "C0009: Stack Pivot")]
    C0009,
    #[serde(rename = "C0055", alias = "C0055: Suspend Thread")]
    C0055,
    #[serde(rename = "C0018", alias = "C0018: Terminate Process")]
    C0018,
    #[serde(rename = "C0039", alias = "C0039: Terminate Thread")]
    C0039,
    #[serde(rename = "C0070", alias = "C0070: Unmap Section View")]
    C0070,
    #[serde(rename = "C0020", alias = "C0020: Use Constant")]
    C0020,
    #[serde(rename = "C0035", alias = "C0035: Wallpaper")]
    C0035,
    #[serde(rename = "C0005", alias = "C0005: WinINet")]
    C0005,
    #[serde(rename = "C0071", alias = "C0071: Write Process Memory")]
    C0071,
    #[serde(rename = "C0052", alias = "C0052: Writes File")]
    C0052,
}

impl std::fmt::Display for MalwareMicroBehaviours {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            MalwareMicroBehaviours::C0007 => C0007,
            MalwareMicroBehaviours::C0040 => C0040,
            MalwareMicroBehaviours::C0015 => C0015,
            MalwareMicroBehaviours::C0008 => C0008,
            MalwareMicroBehaviours::C0043 => C0043,
            MalwareMicroBehaviours::C0019 => C0019,
            MalwareMicroBehaviours::C0032 => C0032,
            MalwareMicroBehaviours::C0024 => C0024,
            MalwareMicroBehaviours::C0060 => C0060,
            MalwareMicroBehaviours::C0033 => C0033,
            MalwareMicroBehaviours::C0045 => C0045,
            MalwareMicroBehaviours::C0046 => C0046,
            MalwareMicroBehaviours::C0016 => C0016,
            MalwareMicroBehaviours::C0042 => C0042,
            MalwareMicroBehaviours::C0017 => C0017,
            MalwareMicroBehaviours::C0038 => C0038,
            MalwareMicroBehaviours::C0068 => C0068,
            MalwareMicroBehaviours::C0069 => C0069,
            MalwareMicroBehaviours::C0059 => C0059,
            MalwareMicroBehaviours::C0029 => C0029,
            MalwareMicroBehaviours::C0011 => C0011,
            MalwareMicroBehaviours::C0053 => C0053,
            MalwareMicroBehaviours::C0025 => C0025,
            MalwareMicroBehaviours::C0031 => C0031,
            MalwareMicroBehaviours::C0048 => C0048,
            MalwareMicroBehaviours::C0047 => C0047,
            MalwareMicroBehaviours::C0026 => C0026,
            MalwareMicroBehaviours::C0027 => C0027,
            MalwareMicroBehaviours::C0028 => C0028,
            MalwareMicroBehaviours::C0064 => C0064,
            MalwareMicroBehaviours::C0034 => C0034,
            MalwareMicroBehaviours::C0004 => C0004,
            MalwareMicroBehaviours::C0044 => C0044,
            MalwareMicroBehaviours::C0021 => C0021,
            MalwareMicroBehaviours::C0049 => C0049,
            MalwareMicroBehaviours::C0002 => C0002,
            MalwareMicroBehaviours::C0061 => C0061,
            MalwareMicroBehaviours::C0006 => C0006,
            MalwareMicroBehaviours::C0014 => C0014,
            MalwareMicroBehaviours::C0037 => C0037,
            MalwareMicroBehaviours::C0003 => C0003,
            MalwareMicroBehaviours::C0023 => C0023,
            MalwareMicroBehaviours::C0058 => C0058,
            MalwareMicroBehaviours::C0063 => C0063,
            MalwareMicroBehaviours::C0030 => C0030,
            MalwareMicroBehaviours::C0065 => C0065,
            MalwareMicroBehaviours::C0066 => C0066,
            MalwareMicroBehaviours::C0010 => C0010,
            MalwareMicroBehaviours::C0051 => C0051,
            MalwareMicroBehaviours::C0056 => C0056,
            MalwareMicroBehaviours::C0036 => C0036,
            MalwareMicroBehaviours::C0054 => C0054,
            MalwareMicroBehaviours::C0012 => C0012,
            MalwareMicroBehaviours::C0050 => C0050,
            MalwareMicroBehaviours::C0072 => C0072,
            MalwareMicroBehaviours::C0041 => C0041,
            MalwareMicroBehaviours::C0057 => C0057,
            MalwareMicroBehaviours::C0001 => C0001,
            MalwareMicroBehaviours::C0009 => C0009,
            MalwareMicroBehaviours::C0055 => C0055,
            MalwareMicroBehaviours::C0018 => C0018,
            MalwareMicroBehaviours::C0039 => C0039,
            MalwareMicroBehaviours::C0070 => C0070,
            MalwareMicroBehaviours::C0020 => C0020,
            MalwareMicroBehaviours::C0035 => C0035,
            MalwareMicroBehaviours::C0005 => C0005,
            MalwareMicroBehaviours::C0071 => C0071,
            MalwareMicroBehaviours::C0052 => C0052,
        };
        f.write_str(description)
    }
}

#[derive(Debug, Error)]
#[error("failed to parse malware micro-behaviour")]
pub struct MalwareMicroBehaviourError;

impl std::str::FromStr for MalwareMicroBehaviours {
    type Err = MalwareMicroBehaviourError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "C0007" | C0007 => Ok(MalwareMicroBehaviours::C0007),
            "C0040" | C0040 => Ok(MalwareMicroBehaviours::C0040),
            "C0015" | C0015 => Ok(MalwareMicroBehaviours::C0015),
            "C0008" | C0008 => Ok(MalwareMicroBehaviours::C0008),
            "C0043" | C0043 => Ok(MalwareMicroBehaviours::C0043),
            "C0019" | C0019 => Ok(MalwareMicroBehaviours::C0019),
            "C0032" | C0032 => Ok(MalwareMicroBehaviours::C0032),
            "C0024" | C0024 => Ok(MalwareMicroBehaviours::C0024),
            "C0060" | C0060 => Ok(MalwareMicroBehaviours::C0060),
            "C0033" | C0033 => Ok(MalwareMicroBehaviours::C0033),
            "C0045" | C0045 => Ok(MalwareMicroBehaviours::C0045),
            "C0046" | C0046 => Ok(MalwareMicroBehaviours::C0046),
            "C0016" | C0016 => Ok(MalwareMicroBehaviours::C0016),
            "C0042" | C0042 => Ok(MalwareMicroBehaviours::C0042),
            "C0017" | C0017 => Ok(MalwareMicroBehaviours::C0017),
            "C0038" | C0038 => Ok(MalwareMicroBehaviours::C0038),
            "C0068" | C0068 => Ok(MalwareMicroBehaviours::C0068),
            "C0069" | C0069 => Ok(MalwareMicroBehaviours::C0069),
            "C0059" | C0059 => Ok(MalwareMicroBehaviours::C0059),
            "C0029" | C0029 => Ok(MalwareMicroBehaviours::C0029),
            "C0011" | C0011 => Ok(MalwareMicroBehaviours::C0011),
            "C0053" | C0053 => Ok(MalwareMicroBehaviours::C0053),
            "C0025" | C0025 => Ok(MalwareMicroBehaviours::C0025),
            "C0031" | C0031 => Ok(MalwareMicroBehaviours::C0031),
            "C0048" | C0048 => Ok(MalwareMicroBehaviours::C0048),
            "C0047" | C0047 => Ok(MalwareMicroBehaviours::C0047),
            "C0026" | C0026 => Ok(MalwareMicroBehaviours::C0026),
            "C0027" | C0027 => Ok(MalwareMicroBehaviours::C0027),
            "C0028" | C0028 => Ok(MalwareMicroBehaviours::C0028),
            "C0064" | C0064 => Ok(MalwareMicroBehaviours::C0064),
            "C0034" | C0034 => Ok(MalwareMicroBehaviours::C0034),
            "C0004" | C0004 => Ok(MalwareMicroBehaviours::C0004),
            "C0044" | C0044 => Ok(MalwareMicroBehaviours::C0044),
            "C0021" | C0021 => Ok(MalwareMicroBehaviours::C0021),
            "C0049" | C0049 => Ok(MalwareMicroBehaviours::C0049),
            "C0002" | C0002 => Ok(MalwareMicroBehaviours::C0002),
            "C0061" | C0061 => Ok(MalwareMicroBehaviours::C0061),
            "C0006" | C0006 => Ok(MalwareMicroBehaviours::C0006),
            "C0014" | C0014 => Ok(MalwareMicroBehaviours::C0014),
            "C0037" | C0037 => Ok(MalwareMicroBehaviours::C0037),
            "C0003" | C0003 => Ok(MalwareMicroBehaviours::C0003),
            "C0023" | C0023 => Ok(MalwareMicroBehaviours::C0023),
            "C0058" | C0058 => Ok(MalwareMicroBehaviours::C0058),
            "C0063" | C0063 => Ok(MalwareMicroBehaviours::C0063),
            "C0030" | C0030 => Ok(MalwareMicroBehaviours::C0030),
            "C0065" | C0065 => Ok(MalwareMicroBehaviours::C0065),
            "C0066" | C0066 => Ok(MalwareMicroBehaviours::C0066),
            "C0010" | C0010 => Ok(MalwareMicroBehaviours::C0010),
            "C0051" | C0051 => Ok(MalwareMicroBehaviours::C0051),
            "C0056" | C0056 => Ok(MalwareMicroBehaviours::C0056),
            "C0036" | C0036 => Ok(MalwareMicroBehaviours::C0036),
            "C0054" | C0054 => Ok(MalwareMicroBehaviours::C0054),
            "C0012" | C0012 => Ok(MalwareMicroBehaviours::C0012),
            "C0050" | C0050 => Ok(MalwareMicroBehaviours::C0050),
            "C0072" | C0072 => Ok(MalwareMicroBehaviours::C0072),
            "C0041" | C0041 => Ok(MalwareMicroBehaviours::C0041),
            "C0057" | C0057 => Ok(MalwareMicroBehaviours::C0057),
            "C0001" | C0001 => Ok(MalwareMicroBehaviours::C0001),
            "C0009" | C0009 => Ok(MalwareMicroBehaviours::C0009),
            "C0055" | C0055 => Ok(MalwareMicroBehaviours::C0055),
            "C0018" | C0018 => Ok(MalwareMicroBehaviours::C0018),
            "C0039" | C0039 => Ok(MalwareMicroBehaviours::C0039),
            "C0070" | C0070 => Ok(MalwareMicroBehaviours::C0070),
            "C0020" | C0020 => Ok(MalwareMicroBehaviours::C0020),
            "C0035" | C0035 => Ok(MalwareMicroBehaviours::C0035),
            "C0005" | C0005 => Ok(MalwareMicroBehaviours::C0005),
            "C0071" | C0071 => Ok(MalwareMicroBehaviours::C0071),
            "C0052" | C0052 => Ok(MalwareMicroBehaviours::C0052),
            _ => Err(MalwareMicroBehaviourError),
        }
    }
}

impl MalwareMicroBehaviours {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::C0007 => C0007,
            Self::C0040 => C0040,
            Self::C0015 => C0015,
            Self::C0008 => C0008,
            Self::C0043 => C0043,
            Self::C0019 => C0019,
            Self::C0032 => C0032,
            Self::C0024 => C0024,
            Self::C0060 => C0060,
            Self::C0033 => C0033,
            Self::C0045 => C0045,
            Self::C0046 => C0046,
            Self::C0016 => C0016,
            Self::C0042 => C0042,
            Self::C0017 => C0017,
            Self::C0038 => C0038,
            Self::C0068 => C0068,
            Self::C0069 => C0069,
            Self::C0059 => C0059,
            Self::C0029 => C0029,
            Self::C0011 => C0011,
            Self::C0053 => C0053,
            Self::C0025 => C0025,
            Self::C0031 => C0031,
            Self::C0048 => C0048,
            Self::C0047 => C0047,
            Self::C0026 => C0026,
            Self::C0027 => C0027,
            Self::C0028 => C0028,
            Self::C0064 => C0064,
            Self::C0034 => C0034,
            Self::C0004 => C0004,
            Self::C0044 => C0044,
            Self::C0021 => C0021,
            Self::C0049 => C0049,
            Self::C0002 => C0002,
            Self::C0061 => C0061,
            Self::C0006 => C0006,
            Self::C0014 => C0014,
            Self::C0037 => C0037,
            Self::C0003 => C0003,
            Self::C0023 => C0023,
            Self::C0058 => C0058,
            Self::C0063 => C0063,
            Self::C0030 => C0030,
            Self::C0065 => C0065,
            Self::C0066 => C0066,
            Self::C0010 => C0010,
            Self::C0051 => C0051,
            Self::C0056 => C0056,
            Self::C0036 => C0036,
            Self::C0054 => C0054,
            Self::C0012 => C0012,
            Self::C0050 => C0050,
            Self::C0072 => C0072,
            Self::C0041 => C0041,
            Self::C0057 => C0057,
            Self::C0001 => C0001,
            Self::C0009 => C0009,
            Self::C0055 => C0055,
            Self::C0018 => C0018,
            Self::C0039 => C0039,
            Self::C0070 => C0070,
            Self::C0020 => C0020,
            Self::C0035 => C0035,
            Self::C0005 => C0005,
            Self::C0071 => C0071,
            Self::C0052 => C0052,
        }
    }
}

pub const E1010: &'static str = "E1010: Application Window Discovery";
pub const E1560: &'static str = "E1560: Archive Collected Data";
pub const E1020: &'static str = "E1020: Automated Exfiltration";
pub const E1510: &'static str = "E1510: Clipboard Modification";
pub const E1059: &'static str = "E1059: Command and Scripting Interpreter";
pub const E1485: &'static str = "E1485: Data Destruction";
pub const E1486: &'static str = "E1486: Data Encrypted for Impact ";
pub const E1190: &'static str = "E1190: Exploit Kit";
pub const E1203: &'static str = "E1203: Exploitation for Client Execution";
pub const E1083: &'static str = "E1083: File and Directory Discovery";
pub const E1643: &'static str = "E1643: Generate Traffic from Victim";
pub const E1564: &'static str = "E1564: Hide Artifacts";
pub const E1105: &'static str = "E1105: Ingress Tool Transfer";
pub const E1056: &'static str = "E1056: Input Capture";
pub const E1112: &'static str = "E1112: Modify Registry";
pub const E1027: &'static str = "E1027: Obfuscated Files or Information";
pub const E1055: &'static str = "E1055: Process Injection";
pub const E1014: &'static str = "E1014: Rootkit";
pub const E1113: &'static str = "E1113: Screen Capture";
pub const E1195: &'static str = "E1195: Supply Chain Compromise";
pub const E1082: &'static str = "E1082: System Information Discovery";
pub const E1569: &'static str = "E1569: System Services";
pub const E1204: &'static str = "E1204: User Execution";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum EnhancedAttackTechniques {
    #[serde(rename = "E1010", alias = "E1010: Application Window Discovery")]
    E1010,
    #[serde(rename = "E1560", alias = "E1560: Archive Collected Data")]
    E1560,
    #[serde(rename = "E1020", alias = "E1020: Automated Exfiltration")]
    E1020,
    #[serde(rename = "E1510", alias = "E1510: Clipboard Modification")]
    E1510,
    #[serde(rename = "E1059", alias = "E1059: Command and Scripting Interpreter")]
    E1059,
    #[serde(rename = "E1485", alias = "E1485: Data Destruction")]
    E1485,
    #[serde(rename = "E1486", alias = "E1486: Data Encrypted for Impact ")]
    E1486,
    #[serde(rename = "E1190", alias = "E1190: Exploit Kit")]
    E1190,
    #[serde(rename = "E1203", alias = "E1203: Exploitation for Client Execution")]
    E1203,
    #[serde(rename = "E1083", alias = "E1083: File and Directory Discovery")]
    E1083,
    #[serde(rename = "E1643", alias = "E1643: Generate Traffic from Victim")]
    E1643,
    #[serde(rename = "E1564", alias = "E1564: Hide Artifacts")]
    E1564,
    #[serde(rename = "E1105", alias = "E1105: Ingress Tool Transfer")]
    E1105,
    #[serde(rename = "E1056", alias = "E1056: Input Capture")]
    E1056,
    #[serde(rename = "E1112", alias = "E1112: Modify Registry")]
    E1112,
    #[serde(rename = "E1027", alias = "E1027: Obfuscated Files or Information")]
    E1027,
    #[serde(rename = "E1055", alias = "E1055: Process Injection")]
    E1055,
    #[serde(rename = "E1014", alias = "E1014: Rootkit")]
    E1014,
    #[serde(rename = "E1113", alias = "E1113: Screen Capture")]
    E1113,
    #[serde(rename = "E1195", alias = "E1195: Supply Chain Compromise")]
    E1195,
    #[serde(rename = "E1082", alias = "E1082: System Information Discovery")]
    E1082,
    #[serde(rename = "E1569", alias = "E1569: System Services")]
    E1569,
    #[serde(rename = "E1204", alias = "E1204: User Execution")]
    E1204,
}

impl std::fmt::Display for EnhancedAttackTechniques {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            EnhancedAttackTechniques::E1010 => E1010,
            EnhancedAttackTechniques::E1560 => E1560,
            EnhancedAttackTechniques::E1020 => E1020,
            EnhancedAttackTechniques::E1510 => E1510,
            EnhancedAttackTechniques::E1059 => E1059,
            EnhancedAttackTechniques::E1485 => E1485,
            EnhancedAttackTechniques::E1486 => E1486,
            EnhancedAttackTechniques::E1190 => E1190,
            EnhancedAttackTechniques::E1203 => E1203,
            EnhancedAttackTechniques::E1083 => E1083,
            EnhancedAttackTechniques::E1643 => E1643,
            EnhancedAttackTechniques::E1564 => E1564,
            EnhancedAttackTechniques::E1105 => E1105,
            EnhancedAttackTechniques::E1056 => E1056,
            EnhancedAttackTechniques::E1112 => E1112,
            EnhancedAttackTechniques::E1027 => E1027,
            EnhancedAttackTechniques::E1055 => E1055,
            EnhancedAttackTechniques::E1014 => E1014,
            EnhancedAttackTechniques::E1113 => E1113,
            EnhancedAttackTechniques::E1195 => E1195,
            EnhancedAttackTechniques::E1082 => E1082,
            EnhancedAttackTechniques::E1569 => E1569,
            EnhancedAttackTechniques::E1204 => E1204,
        };
        f.write_str(description)
    }
}

#[derive(Debug, Error)]
#[error("failed to parse enhanced ATT&CK techniques")]
pub struct EnhancedAttackTechniqueError;

impl std::str::FromStr for EnhancedAttackTechniques {
    type Err = EnhancedAttackTechniqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "E1010" | E1010 => Ok(EnhancedAttackTechniques::E1010),
            "E1560" | E1560 => Ok(EnhancedAttackTechniques::E1560),
            "E1020" | E1020 => Ok(EnhancedAttackTechniques::E1020),
            "E1510" | E1510 => Ok(EnhancedAttackTechniques::E1510),
            "E1059" | E1059 => Ok(EnhancedAttackTechniques::E1059),
            "E1485" | E1485 => Ok(EnhancedAttackTechniques::E1485),
            "E1486" | E1486 => Ok(EnhancedAttackTechniques::E1486),
            "E1190" | E1190 => Ok(EnhancedAttackTechniques::E1190),
            "E1203" | E1203 => Ok(EnhancedAttackTechniques::E1203),
            "E1083" | E1083 => Ok(EnhancedAttackTechniques::E1083),
            "E1643" | E1643 => Ok(EnhancedAttackTechniques::E1643),
            "E1564" | E1564 => Ok(EnhancedAttackTechniques::E1564),
            "E1105" | E1105 => Ok(EnhancedAttackTechniques::E1105),
            "E1056" | E1056 => Ok(EnhancedAttackTechniques::E1056),
            "E1112" | E1112 => Ok(EnhancedAttackTechniques::E1112),
            "E1027" | E1027 => Ok(EnhancedAttackTechniques::E1027),
            "E1055" | E1055 => Ok(EnhancedAttackTechniques::E1055),
            "E1014" | E1014 => Ok(EnhancedAttackTechniques::E1014),
            "E1113" | E1113 => Ok(EnhancedAttackTechniques::E1113),
            "E1195" | E1195 => Ok(EnhancedAttackTechniques::E1195),
            "E1082" | E1082 => Ok(EnhancedAttackTechniques::E1082),
            "E1569" | E1569 => Ok(EnhancedAttackTechniques::E1569),
            "E1204" | E1204 => Ok(EnhancedAttackTechniques::E1204),
            _ => Err(EnhancedAttackTechniqueError),
        }
    }
}

impl EnhancedAttackTechniques {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::E1010 => E1010,
            Self::E1560 => E1560,
            Self::E1020 => E1020,
            Self::E1510 => E1510,
            Self::E1059 => E1059,
            Self::E1485 => E1485,
            Self::E1486 => E1486,
            Self::E1190 => E1190,
            Self::E1203 => E1203,
            Self::E1083 => E1083,
            Self::E1643 => E1643,
            Self::E1564 => E1564,
            Self::E1105 => E1105,
            Self::E1056 => E1056,
            Self::E1112 => E1112,
            Self::E1027 => E1027,
            Self::E1055 => E1055,
            Self::E1014 => E1014,
            Self::E1113 => E1113,
            Self::E1195 => E1195,
            Self::E1082 => E1082,
            Self::E1569 => E1569,
            Self::E1204 => E1204,
        }
    }
}

pub const F0013: &'static str = "F0013: Bootkit";
pub const F0009: &'static str = "F0009: Component Firmware";
pub const F0004: &'static str = "F0004: Disable or Evade Security Tools";
pub const F0014: &'static str = "F0014: Disk Wipe";
pub const F0005: &'static str = "F0005: Hidden Files and Directories";
pub const F0015: &'static str = "F0015: Hijack Execution Flow";
pub const F0006: &'static str = "F0006: Indicator Blocking";
pub const F0016: &'static str = "F0016: Install Certificate";
pub const F0010: &'static str = "F0010: Kernel Modules and Extensions";
pub const F0002: &'static str = "F0002: Keylogging";
pub const F0011: &'static str = "F0011: Modify Existing Service";
pub const F0012: &'static str = "F0012: Registry Run Keys / Startup Folder";
pub const F0007: &'static str = "F0007: Self Deletion";
pub const F0001: &'static str = "F0001: Software Packing";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum EnhancedAttackSubTechniques {
    #[serde(rename = "F0013", alias = "F0013: Bootkit")]
    F0013,
    #[serde(rename = "F0009", alias = "F0009: Component Firmware")]
    F0009,
    #[serde(rename = "F0004", alias = "F0004: Disable or Evade Security Tools")]
    F0004,
    #[serde(rename = "F0014", alias = "F0014: Disk Wipe")]
    F0014,
    #[serde(rename = "F0005", alias = "F0005: Hidden Files and Directories")]
    F0005,
    #[serde(rename = "F0015", alias = "F0015: Hijack Execution Flow")]
    F0015,
    #[serde(rename = "F0006", alias = "F0006: Indicator Blocking")]
    F0006,
    #[serde(rename = "F0016", alias = "F0016: Install Certificate")]
    F0016,
    #[serde(rename = "F0010", alias = "F0010: Kernel Modules and Extensions")]
    F0010,
    #[serde(rename = "F0002", alias = "F0002: Keylogging")]
    F0002,
    #[serde(rename = "F0011", alias = "F0011: Modify Existing Service")]
    F0011,
    #[serde(rename = "F0012", alias = "F0012: Registry Run Keys / Startup Folder")]
    F0012,
    #[serde(rename = "F0007", alias = "F0007: Self Deletion")]
    F0007,
    #[serde(rename = "F0001", alias = "F0001: Software Packing")]
    F0001,
}

impl std::fmt::Display for EnhancedAttackSubTechniques {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            EnhancedAttackSubTechniques::F0013 => F0013,
            EnhancedAttackSubTechniques::F0009 => F0009,
            EnhancedAttackSubTechniques::F0004 => F0004,
            EnhancedAttackSubTechniques::F0014 => F0014,
            EnhancedAttackSubTechniques::F0005 => F0005,
            EnhancedAttackSubTechniques::F0015 => F0015,
            EnhancedAttackSubTechniques::F0006 => F0006,
            EnhancedAttackSubTechniques::F0016 => F0016,
            EnhancedAttackSubTechniques::F0010 => F0010,
            EnhancedAttackSubTechniques::F0002 => F0002,
            EnhancedAttackSubTechniques::F0011 => F0011,
            EnhancedAttackSubTechniques::F0012 => F0012,
            EnhancedAttackSubTechniques::F0007 => F0007,
            EnhancedAttackSubTechniques::F0001 => F0001,
        };
        f.write_str(description)
    }
}

#[derive(Debug, Error)]
#[error("failed to parse enhanced malware ATT&CK sub-technique")]
pub struct EnhancedAttackSubTechniqueError;

impl std::str::FromStr for EnhancedAttackSubTechniques {
    type Err = EnhancedAttackSubTechniqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "F0013" | F0013 => Ok(EnhancedAttackSubTechniques::F0013),
            "F0009" | F0009 => Ok(EnhancedAttackSubTechniques::F0009),
            "F0004" | F0004 => Ok(EnhancedAttackSubTechniques::F0004),
            "F0014" | F0014 => Ok(EnhancedAttackSubTechniques::F0014),
            "F0005" | F0005 => Ok(EnhancedAttackSubTechniques::F0005),
            "F0015" | F0015 => Ok(EnhancedAttackSubTechniques::F0015),
            "F0006" | F0006 => Ok(EnhancedAttackSubTechniques::F0006),
            "F0016" | F0016 => Ok(EnhancedAttackSubTechniques::F0016),
            "F0010" | F0010 => Ok(EnhancedAttackSubTechniques::F0010),
            "F0002" | F0002 => Ok(EnhancedAttackSubTechniques::F0002),
            "F0011" | F0011 => Ok(EnhancedAttackSubTechniques::F0011),
            "F0012" | F0012 => Ok(EnhancedAttackSubTechniques::F0012),
            "F0007" | F0007 => Ok(EnhancedAttackSubTechniques::F0007),
            "F0001" | F0001 => Ok(EnhancedAttackSubTechniques::F0001),
            _ => Err(EnhancedAttackSubTechniqueError),
        }
    }
}

impl EnhancedAttackSubTechniques {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::F0013 => F0013,
            Self::F0009 => F0009,
            Self::F0004 => F0004,
            Self::F0014 => F0014,
            Self::F0005 => F0005,
            Self::F0015 => F0015,
            Self::F0006 => F0006,
            Self::F0016 => F0016,
            Self::F0010 => F0010,
            Self::F0002 => F0002,
            Self::F0011 => F0011,
            Self::F0012 => F0012,
            Self::F0007 => F0007,
            Self::F0001 => F0001,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MBC {
    MalwareObjective(MalwareObjectives),
    MalwareMicroObjective(MalwareMicroObjectives),
    MalwareBehaviour(MalwareBehaviours),
    MalwareMicroBehaviour(MalwareMicroBehaviours),
    EnhancedAttackTechnique(EnhancedAttackTechniques),
    EnhancedAttackSubTechnique(EnhancedAttackSubTechniques),
}

#[derive(Debug, Error)]
#[error("failed to parse malware behaviour")]
pub struct MBCError;

impl std::str::FromStr for MBC {
    type Err = MBCError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(obj) = s.parse::<MalwareObjectives>() {
            return Ok(Self::MalwareObjective(obj));
        }
        if let Ok(obj) = s.parse::<MalwareMicroObjectives>() {
            return Ok(Self::MalwareMicroObjective(obj));
        }
        if let Ok(obj) = s.parse::<MalwareBehaviours>() {
            return Ok(Self::MalwareBehaviour(obj));
        }
        if let Ok(obj) = s.parse::<MalwareMicroBehaviours>() {
            return Ok(Self::MalwareMicroBehaviour(obj));
        }
        if let Ok(obj) = s.parse::<EnhancedAttackTechniques>() {
            return Ok(Self::EnhancedAttackTechnique(obj));
        }
        if let Ok(obj) = s.parse::<EnhancedAttackSubTechniques>() {
            return Ok(Self::EnhancedAttackSubTechnique(obj));
        }
        Err(MBCError)
    }
}

impl std::fmt::Display for MBC {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalwareObjective(obj) => obj.fmt(f),
            Self::MalwareMicroObjective(obj) => obj.fmt(f),
            Self::MalwareBehaviour(obj) => obj.fmt(f),
            Self::MalwareMicroBehaviour(obj) => obj.fmt(f),
            Self::EnhancedAttackTechnique(obj) => obj.fmt(f),
            Self::EnhancedAttackSubTechnique(obj) => obj.fmt(f),
        }
    }
}

impl MBC {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MalwareObjective(obj) => obj.as_str(),
            Self::MalwareMicroObjective(obj) => obj.as_str(),
            Self::MalwareBehaviour(obj) => obj.as_str(),
            Self::MalwareMicroBehaviour(obj) => obj.as_str(),
            Self::EnhancedAttackTechnique(obj) => obj.as_str(),
            Self::EnhancedAttackSubTechnique(obj) => obj.as_str(),
        }
    }
}
