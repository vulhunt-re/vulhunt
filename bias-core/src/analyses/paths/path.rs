use std::borrow::Borrow;
use std::ops::Deref;
use std::{iter, slice};

use crate::analyses::symbolic::typed::{
    AliasVisitor, ContextualTypeResolver, TypedAliasVisitable, TypedAliasVisitor,
};
use crate::kb::block::{CodeBlockId, CodeBlockTable};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodePathBlockRef {
    block: CodeBlockId,
    index: usize,
}

impl CodePathBlockRef {
    #[inline]
    pub fn id(&self) -> CodeBlockId {
        self.block
    }

    #[inline]
    pub fn index(&self) -> usize {
        self.index
    }
}

impl AsRef<CodeBlockId> for CodePathBlockRef {
    fn as_ref(&self) -> &CodeBlockId {
        &self.block
    }
}

impl AsRef<CodePathBlockRef> for CodePathBlockRef {
    fn as_ref(&self) -> &CodePathBlockRef {
        &self
    }
}

impl Borrow<CodeBlockId> for CodePathBlockRef {
    fn borrow(&self) -> &CodeBlockId {
        &self.block
    }
}

impl Deref for CodePathBlockRef {
    type Target = CodeBlockId;

    fn deref(&self) -> &Self::Target {
        &self.block
    }
}

#[derive(Debug, Clone, Default)]
pub struct CodePath {
    blocks: Vec<CodeBlockId>,
    limit: Option<usize>,
}

impl From<Vec<CodeBlockId>> for CodePath {
    fn from(path: Vec<CodeBlockId>) -> Self {
        Self {
            blocks: path,
            limit: None,
        }
    }
}

impl FromIterator<CodeBlockId> for CodePath {
    fn from_iter<T: IntoIterator<Item = CodeBlockId>>(iter: T) -> Self {
        Self::from(Vec::from_iter(iter))
    }
}

impl CodePath {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with(limit: impl Into<Option<usize>>) -> Self {
        Self {
            limit: limit.into(),
            ..Default::default()
        }
    }

    #[inline]
    pub fn push(&mut self, block: CodeBlockId) -> bool {
        if !matches!(self.limit, Some(n) if self.len() >= n) {
            self.blocks.push(block);
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn entry(&self) -> CodePathBlockRef {
        CodePathBlockRef {
            index: 0,
            block: self.blocks[0],
        }
    }

    #[inline]
    pub fn pred(&self, block: impl AsRef<CodePathBlockRef>) -> Option<CodePathBlockRef> {
        let block = block.as_ref();
        let index = block.index.checked_sub(1)?;
        self.blocks
            .get(index)
            .map(|&block| CodePathBlockRef { block, index })
    }

    #[inline]
    pub fn succ(&self, block: impl AsRef<CodePathBlockRef>) -> Option<CodePathBlockRef> {
        let block = block.as_ref();
        let index = block.index.checked_add(1)?;
        self.blocks
            .get(index)
            .map(|&block| CodePathBlockRef { block, index })
    }

    #[inline]
    pub fn iter(&self) -> CodePathIter<'_> {
        CodePathIter(self.blocks.iter().enumerate())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }
}

#[derive(Clone)]
pub struct CodePathIter<'a>(iter::Enumerate<slice::Iter<'a, CodeBlockId>>);

impl<'a> Iterator for CodePathIter<'a> {
    type Item = CodePathBlockRef;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|(index, &block)| CodePathBlockRef { index, block })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl<'a> ExactSizeIterator for CodePathIter<'a> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a> DoubleEndedIterator for CodePathIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0
            .next_back()
            .map(|(index, &block)| CodePathBlockRef { index, block })
    }
}

pub struct CodePathVisitor<'a> {
    path: &'a CodePath,
    blocks: &'a CodeBlockTable,
}

impl<'a> CodePathVisitor<'a> {
    pub fn new(path: &'a CodePath, blocks: &'a CodeBlockTable) -> Self {
        Self { path, blocks }
    }
}

impl<'path> TypedAliasVisitable for CodePathVisitor<'path> {
    fn visit_aliases_with<'a, 'b, T, V>(
        &self,
        driver: &mut TypedAliasVisitor<'a, 'b, T>,
        visitor: &mut V,
    ) where
        T: ContextualTypeResolver<'a>,
        V: AliasVisitor<'a, 'b, T>,
    {
        for bref in self.path.iter() {
            let blk = &self.blocks[bref.block];
            blk.visit_aliases_with(driver, visitor)
        }
    }
}
