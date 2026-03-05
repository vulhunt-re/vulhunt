use std::fs;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::{io, str};

use thiserror::Error;
use tree_sitter::{LanguageError, Parser, Range};
use walkdir::WalkDir;

use super::traits::EntityExtractor;

#[derive(Debug, Error)]
pub enum ExtractorError {
    #[error("could not read file `{0}`: {1}")]
    FileIo(PathBuf, io::Error),
    #[error("could not initialise parser: {0}")]
    Language(#[from] LanguageError),
    #[error("could not parse source")]
    Parse,
}

impl ExtractorError {
    pub fn file(path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> Self {
        let path = path.into();
        move |e| Self::FileIo(path, e)
    }
}

pub struct Entity<T> {
    range: Range,
    data: T,
}

impl<T> Entity<T> {
    pub fn entity<'a>(&self, source: &'a str) -> &'a str {
        let range = &source.as_bytes()[self.range.start_byte..self.range.end_byte];
        str::from_utf8(range).unwrap()
    }

    pub fn range(&self) -> &Range {
        &self.range
    }

    pub fn data(&self) -> &T {
        &self.data
    }

    pub fn into_data(self) -> T {
        self.data
    }

    pub fn into_parts(self) -> (Range, T) {
        (self.range, self.data)
    }
}

pub struct FileEntities<T> {
    path: PathBuf,
    source: String,
    entities: Vec<Entity<T>>,
}

impl<T> FileEntities<T> {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn entities(&self) -> impl ExactSizeIterator<Item = &Entity<T>> {
        self.entities.iter()
    }
}

pub struct Extractor<'a, T>
where
    T: EntityExtractor<'a>,
{
    parser: Parser,
    nodeid: u16,
    extractor: T,
    _marker: PhantomData<&'a T>,
}

impl<'a, T> Extractor<'a, T>
where
    T: EntityExtractor<'a>,
{
    pub fn new() -> Result<Self, ExtractorError>
    where
        T: Default,
    {
        Self::new_with(T::default())
    }

    pub fn new_with(extractor: T) -> Result<Self, ExtractorError> {
        let mut parser = Parser::new();

        let language = extractor.language();
        let nodeid = language.id_for_node_kind(T::NODE, T::NAMED);

        parser.set_language(&language)?;

        Ok(Self {
            parser,
            nodeid,
            extractor,
            _marker: PhantomData,
        })
    }

    pub fn extract(&mut self, source: &str) -> Result<Vec<Entity<T::Target>>, ExtractorError> {
        let parsed = self
            .parser
            .parse(source, None)
            .ok_or_else(|| ExtractorError::Parse)?;

        let mut walker = parsed.walk();
        let mut entities = Vec::new();

        let mut worklist = vec![parsed.root_node()];

        while let Some(node) = worklist.pop() {
            if node.kind_id() == self.nodeid {
                if let Some(data) = self.extractor.extract(node, &mut walker, source) {
                    entities.push(Entity {
                        range: node.range(),
                        data,
                    });

                    if !T::EXTRACT_WITHIN_MATCHES {
                        continue;
                    }
                }
            }

            for child in node.children(&mut walker) {
                worklist.push(child);
            }
        }

        Ok(entities)
    }

    pub fn extract_first(
        &mut self,
        source: &str,
    ) -> Result<Option<Entity<T::Target>>, ExtractorError> {
        let parsed = self
            .parser
            .parse(source, None)
            .ok_or_else(|| ExtractorError::Parse)?;
        let mut walker = parsed.walk();
        let mut worklist = vec![parsed.root_node()];

        while let Some(node) = worklist.pop() {
            if node.kind_id() == self.nodeid {
                if let Some(data) = self.extractor.extract(node, &mut walker, source) {
                    return Ok(Some(Entity {
                        range: node.range(),
                        data,
                    }));
                }
            }

            for child in node.children(&mut walker) {
                worklist.push(child);
            }
        }

        Ok(None)
    }

    pub fn extract_file(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<FileEntities<T::Target>, ExtractorError> {
        let path = path.as_ref();
        let source = fs::read_to_string(path).map_err(ExtractorError::file(path))?;
        self.extract(&source).map(|entities| FileEntities {
            path: path.to_owned(),
            source,
            entities,
        })
    }

    pub fn extract_directory(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<Vec<FileEntities<T::Target>>, ExtractorError> {
        let mut walker = WalkDir::new(path).into_iter();
        let mut entities = Vec::new();

        while let Some(entry) = walker.next() {
            let Ok(entry) = entry else { continue };

            if !entry.file_type().is_file() {
                continue;
            }

            let file_entities = self.extract_file(entry.path())?;

            entities.push(file_entities);
        }

        Ok(entities)
    }
}
