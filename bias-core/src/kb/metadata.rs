#[derive(serde::Serialize, serde::Deserialize)]
pub enum Format {
    PE,
    TE,
    ELF,
    MachO,
    Other(String),
}

impl<'a> From<&'a str> for Format {
    fn from(fmt: &'a str) -> Self {
        Self::new(fmt)
    }
}

impl From<String> for Format {
    fn from(fmt: String) -> Self {
        Self::new(fmt)
    }
}

impl Format {
    pub fn new(format: impl Into<String>) -> Self {
        let format = format.into();
        if format.eq_ignore_ascii_case("PE") {
            Self::PE
        } else if format.eq_ignore_ascii_case("TE") {
            Self::TE
        } else if format.eq_ignore_ascii_case("ELF") {
            Self::ELF
        } else if format.eq_ignore_ascii_case("Mach-O") {
            Self::MachO
        } else {
            Self::Other(format)
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Metadata {
    input_path: String,
    input_format: Format,
    input_size: u32,
    input_md5: [u8; 16],
    input_sha256: [u8; 32],
    exporter: String,
}

impl Metadata {
    pub fn new(
        input_path: impl Into<String>,
        input_format: impl Into<Format>,
        input_size: u32,
        input_md5: [u8; 16],
        input_sha256: [u8; 32],
        exporter: impl Into<String>,
    ) -> Self {
        Self {
            input_path: input_path.into(),
            input_format: input_format.into(),
            input_size,
            input_md5,
            input_sha256,
            exporter: exporter.into(),
        }
    }
}
