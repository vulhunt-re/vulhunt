use std::path::Path;

use bias::platform::common::PlatformAttributeMap;
use bias_core::efi::EFIModuleType;
use bias_core::prelude::Endian;
use binaryninja::Endianness;
use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::data_buffer::DataBuffer;

use crate::error::BNDBSourceError;

pub(crate) fn convert_endian(e: Endianness) -> Endian {
    if e == Endianness::LittleEndian {
        Endian::Little
    } else {
        Endian::Big
    }
}

pub(crate) fn normalise_arm_address(addr: u64, is_arm: bool) -> u64 {
    if is_arm { addr & !1 } else { addr }
}

pub(crate) fn is_thumb_mode(addr: u64) -> bool {
    (addr & 1) != 0
}

pub(crate) fn view_bytes(view: &BinaryView, path: &Path) -> Result<DataBuffer, BNDBSourceError> {
    let raw = view
        .raw_view()
        .ok_or_else(|| BNDBSourceError::RawView(path.to_owned()))?;
    let bytes = raw
        .read_buffer(0, raw.len() as usize)
        .map_err(|_| BNDBSourceError::BytesRead(path.to_owned()))?;
    Ok(bytes)
}

pub(crate) fn infer_efi_module_kind(
    bytes: &[u8],
    attrs: Option<&PlatformAttributeMap>,
) -> EFIModuleType {
    const TE_SIGNATURE: [u8; 2] = [0x56, 0x5A];

    if let Some(kind) = attrs.and_then(|a| a.get_attr::<EFIModuleType>("kind")) {
        return kind;
    }

    // NOTE: this is not 100% foolproof, but generally holds
    if bytes.len() >= 2 && bytes[0..2] == TE_SIGNATURE {
        EFIModuleType::PeiModule
    } else {
        EFIModuleType::DxeDriver
    }
}
