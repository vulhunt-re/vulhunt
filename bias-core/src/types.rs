use std::fmt::Display;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum Confidence {
    Unlikely,
    Possible,
    Likely,
    Certain,
}

impl Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unlikely => write!(f, "unlikely"),
            Self::Possible => write!(f, "possible"),
            Self::Likely => write!(f, "likely"),
            Self::Certain => write!(f, "certain"),
        }
    }
}
