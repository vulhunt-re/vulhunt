use std::borrow::Cow;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Cursor, Read};
use std::ops::Deref;
use std::path::Path;
use std::str;
use std::sync::Arc;

use bias_core::analyses::blocks::{CodeBlockBounds, CODE_BLOCK_BOUNDS};
use bias_core::prelude::*;

use lancelot_flirt::{FlirtSignatureSet, Name, Symbol};
use smallvec::SmallVec;

pub use lancelot_flirt::FlirtSignature as FLIRTSignature;
pub use lancelot_flirt::FlirtSignatureSet as FLIRTSignatureSet;

use thiserror::Error;

pub const FLIRT_SIGNATURES: Uuid = uuid("4B14AEC2-FA5A-4CC7-8CF1-884AC82A4204");

#[derive(Debug, Error)]
pub enum FLIRTError {
    #[error("cannot load FLIRT signatures: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot parse FLIRT signatures: {0}")]
    PatParse(#[from] lancelot_flirt::pat::PatError),
    #[error("cannot parse FLIRT signatures: {0}")]
    SigParse(#[from] lancelot_flirt::sig::SigError),
    #[error("cannot parse bytes as UTF-8 string: {0}")]
    StrParse(#[from] str::Utf8Error),
}

pub type FLIRTMatches = AHashMap<FunctionId, SmallVec<[FLIRTSignature; 1]>>;
pub type FLIRTSymbols = AHashMap<FunctionId, SmallVec<[String; 1]>>;

pub struct FLIRTDB {
    signatures: Vec<FlirtSignatureSet>,
}

#[derive(Clone)]
pub struct FrozenFLIRTDB(Arc<FLIRTDB>);

impl Deref for FrozenFLIRTDB {
    type Target = FLIRTDB;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl FLIRTDB {
    pub fn new() -> Self {
        Self {
            signatures: Default::default(),
        }
    }

    #[inline]
    fn decompress_bytes(bytes: &[u8]) -> Result<Vec<u8>, FLIRTError> {
        let mut dbytes = Vec::new();
        let mut d = flate2::read::GzDecoder::new(Cursor::new(bytes));
        d.read_to_end(&mut dbytes)?;
        Ok(dbytes)
    }

    #[inline]
    fn decompress_str(bytes: &[u8]) -> Result<String, FLIRTError> {
        let mut dstr = String::new();
        let mut d = flate2::read::GzDecoder::new(Cursor::new(bytes));
        d.read_to_string(&mut dstr)?;
        Ok(dstr)
    }

    #[inline]
    fn map_file_bytes<T, F>(path: impl AsRef<Path>, f: F) -> Result<T, FLIRTError>
    where
        F: FnOnce(Cow<[u8]>) -> Result<T, FLIRTError>,
    {
        let file = unsafe { memmap2::Mmap::map(&File::open(path)?)? };
        let bytes = if !file.starts_with(b"IDASGN") {
            Cow::Owned(Self::decompress_bytes(&*file)?)
        } else {
            Cow::Borrowed(&*file)
        };

        f(bytes)
    }

    #[inline]
    fn map_file_str<T, F>(path: impl AsRef<Path>, f: F) -> Result<T, FLIRTError>
    where
        F: FnOnce(Cow<str>) -> Result<T, FLIRTError>,
    {
        let path = path.as_ref();
        let file = unsafe { memmap2::Mmap::map(&File::open(path)?)? };
        let pstr = if matches!(path.extension(), Some(ext) if ext == "gz") {
            Cow::Owned(Self::decompress_str(&*file)?)
        } else {
            Cow::Borrowed(str::from_utf8(&*file)?)
        };

        f(pstr)
    }

    #[inline]
    pub fn from_pat_file(path: impl AsRef<Path>) -> Result<Self, FLIRTError> {
        Self::map_file_str(path, |pstr| Self::from_pat(pstr))
    }

    #[inline]
    pub fn from_sig_file(path: impl AsRef<Path>) -> Result<Self, FLIRTError> {
        Self::map_file_bytes(path, |bytes| Self::from_sig(bytes))
    }

    #[inline]
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, FLIRTError> {
        let file = unsafe { memmap2::Mmap::map(&File::open(path)?)? };
        match Self::from_bytes(&file) {
            Ok(s) => Ok(s),
            _ => {
                let dbytes = Self::decompress_bytes(&*file)?;
                Self::from_bytes(dbytes)
            }
        }
    }

    #[inline]
    pub fn from_bytes(s: impl AsRef<[u8]>) -> Result<Self, FLIRTError> {
        let bytes = s.as_ref();
        if bytes.starts_with(b"IDASIG") {
            Self::from_sig(bytes)
        } else {
            Self::from_pat(str::from_utf8(bytes)?)
        }
    }

    #[inline]
    pub fn from_str(s: impl AsRef<str>) -> Result<Self, FLIRTError> {
        Self::from_pat(s)
    }

    #[inline]
    pub fn from_pat(pat: impl AsRef<str>) -> Result<Self, FLIRTError> {
        let mut slf = Self::new();
        slf.extend_with_pat(pat)?;
        Ok(slf)
    }

    #[inline]
    pub fn from_sig(sig: impl AsRef<[u8]>) -> Result<Self, FLIRTError> {
        let mut slf = Self::new();
        slf.extend_with_sig(sig)?;
        Ok(slf)
    }

    #[inline]
    pub fn extend_with_pat_file(&mut self, path: impl AsRef<Path>) -> Result<(), FLIRTError> {
        Self::map_file_str(path, |pstr| self.extend_with_pat(pstr))
    }

    #[inline]
    pub fn extend_with_pat(&mut self, pat: impl AsRef<str>) -> Result<(), FLIRTError> {
        match lancelot_flirt::pat::parse(pat.as_ref()) {
            Ok(sigs) => {
                self.signatures
                    .push(FlirtSignatureSet::with_signatures(sigs));
                Ok(())
            }
            Err(e) => {
                let e = e.downcast::<lancelot_flirt::pat::PatError>().unwrap();
                Err(e.into())
            }
        }
    }

    #[inline]
    pub fn extend_with_sig_file(&mut self, path: impl AsRef<Path>) -> Result<(), FLIRTError> {
        Self::map_file_bytes(path, |bytes| self.extend_with_sig(bytes))
    }

    #[inline]
    pub fn extend_with_sig(&mut self, pat: impl AsRef<[u8]>) -> Result<(), FLIRTError> {
        match lancelot_flirt::sig::parse(pat.as_ref()) {
            Ok(sigs) => {
                self.signatures
                    .push(FlirtSignatureSet::with_signatures(sigs));
                Ok(())
            }
            Err(e) => {
                let e = e.downcast::<lancelot_flirt::sig::SigError>().unwrap();
                Err(e.into())
            }
        }
    }

    #[inline]
    pub fn freeze(self) -> FrozenFLIRTDB {
        FrozenFLIRTDB(Arc::new(self))
    }

    #[inline]
    fn guess_reference_target(
        project: &Project,
        bounds: &CodeBlockBounds,
        address: Address,
        offset: i64,
    ) -> Option<Address> {
        let target = if offset < 0 {
            address - (offset.abs() as u64)
        } else {
            address + (offset as u64)
        };

        let (_, &bid) = bounds.get(target)?;

        let node = project.code_blocks()[bid].node();
        for edge in project.icfg().edges_directed(node, Direction::Outgoing) {
            if edge.weight().is_call() || edge.weight().is_branch() || edge.weight().is_indirect() {
                let tblk = &project.code_blocks()[project.icfg()[edge.target()]].address();
                if project.functions().contains_point(tblk) {
                    return Some(*tblk);
                }
            }
        }

        None
    }

    pub fn matches_into(
        &self,
        project: &Project,
        bounds: &CodeBlockBounds,
        fmatches: &mut FLIRTMatches,
        fsyms: &mut FLIRTSymbols,
    ) {
        let memory = project.memory();

        for sigset in self.signatures.iter() {
            let mut worklist = project.functions().values().collect::<VecDeque<_>>();

            'outer: while let Some(f) = worklist.pop_front() {
                let address = f.address();
                let mut candidates = SmallVec::<[_; 1]>::new();
                let mut matches = true;

                let Some(f_last) = f
                    .blocks_with(project.code_blocks())
                    .map(|blk| blk.next_address())
                    .max()
                else {
                    continue;
                };

                let size = f_last.offset() - address.offset();

                let Ok(bytes) = memory.view_bytes(address, size as _) else {
                    continue;
                };

                let signatures = sigset.r#match(&bytes);

                for signature in signatures.into_iter() {
                    'name: for name in signature.names.iter() {
                        let Symbol::Reference(Name {
                            offset,
                            name: wanted_name,
                        }) = name
                        else {
                            continue;
                        };

                        if wanted_name == "." {
                            if Self::guess_reference_target(project, bounds, address, *offset)
                                .is_some()
                            {
                                continue;
                            } else {
                                matches = false;
                                break;
                            }
                        }

                        if let Some(target) =
                            Self::guess_reference_target(project, bounds, address, *offset)
                                .and_then(|addr| project.functions().get_point(addr))
                        {
                            let target_signatures = if let Some(sigs) = fmatches.get(&target.id()) {
                                sigs
                            } else {
                                worklist.push_back(f);
                                continue 'outer;
                            };

                            let mut matches_name = false;
                            'sig: for tsig in target_signatures.iter() {
                                for name in tsig.names.iter() {
                                    match name {
                                        Symbol::Reference(_) => continue,
                                        Symbol::Local(n) | Symbol::Public(n) => {
                                            if n.offset == 0 && n.name == *wanted_name {
                                                matches_name = true;
                                                break 'sig;
                                            }
                                        }
                                    }
                                }
                            }

                            if !matches_name {
                                matches = false;
                                break 'name;
                            }
                        } else {
                            matches = false;
                            break;
                        }
                    }

                    if matches {
                        candidates.push(signature.to_owned());
                    }
                }

                // handle candidates such that we propagate non-zero offsets
                for candidate in candidates.iter() {
                    for name in candidate.names.iter() {
                        let (Symbol::Local(n) | Symbol::Public(n)) = name else {
                            continue;
                        };

                        let offset = n.offset;

                        if offset == 0 {
                            // for this function
                            fsyms.entry(f.id()).or_default().push(n.name.to_owned());
                        } else if offset > 0 {
                            let nfaddr = f.address() + offset as usize;
                            if let Some(nf) = project.function_at(nfaddr) {
                                fsyms.entry(nf.id()).or_default().push(n.name.to_owned());
                            }
                        } else {
                            let nfaddr = f.address() - offset as usize;
                            if let Some(nf) = project.function_at(nfaddr) {
                                fsyms.entry(nf.id()).or_default().push(n.name.to_owned());
                            }
                        }

                        // for some other function
                    }
                }

                if matches {
                    fmatches.entry(f.id()).or_default().extend(candidates);
                }
            }
        }
    }

    pub fn matches(
        &self,
        project: &Project,
        bounds: &CodeBlockBounds,
    ) -> (FLIRTMatches, FLIRTSymbols) {
        let mut matches = FLIRTMatches::new();
        let mut symbols = FLIRTSymbols::new();
        self.matches_into(project, bounds, &mut matches, &mut symbols);
        (matches, symbols)
    }
}

#[derive(Clone)]
pub struct FLIRT {
    matches: AHashMap<FunctionId, SmallVec<[FLIRTSignature; 1]>>,
    symbols: AHashMap<FunctionId, SmallVec<[String; 1]>>,
    signatures: FrozenFLIRTDB,
}

impl AnalysisInfo for FLIRT {
    const NAME: &'static str = "FLIRT Signatures";
    const DEPENDENCIES: &'static [AnalysisSchedule] = &[AnalysisSchedule::After(CODE_BLOCK_BOUNDS)];
    const UUID: Uuid = FLIRT_SIGNATURES;
}

impl FLIRT {
    pub fn new(signatures: FrozenFLIRTDB) -> Self {
        Self {
            matches: AHashMap::default(),
            symbols: AHashMap::default(),
            signatures,
        }
    }

    #[inline]
    pub fn matches(&self) -> &AHashMap<FunctionId, SmallVec<[FLIRTSignature; 1]>> {
        &self.matches
    }

    #[inline]
    pub fn symbols(&self) -> &AHashMap<FunctionId, SmallVec<[String; 1]>> {
        &self.symbols
    }
}

impl Analysis for FLIRT {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }

    fn dependencies(&self) -> &[AnalysisSchedule] {
        Self::DEPENDENCIES
    }

    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let bounds = project.get_analysis::<CodeBlockBounds>();

        self.signatures
            .matches_into(project, bounds, &mut self.matches, &mut self.symbols);

        Ok(())
    }
}

