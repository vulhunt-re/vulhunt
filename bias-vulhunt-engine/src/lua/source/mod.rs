use std::borrow::Cow;

use mlua::{Scope, UserData, UserDataFields, UserDataMethods};

pub mod extract;

use extract::languages::{Language, Parser, Tree};

use thiserror::Error;

pub mod grammar;
pub use grammar::NodeTypes;

pub mod node;
pub use node::NodeRef;

#[derive(Debug, Error)]
pub enum SourceCodeError {
    #[error("cannot parse language data: {0}")]
    Language(anyhow::Error),
    #[error("cannot parse source: {0}")]
    Parse(anyhow::Error),
}

impl SourceCodeError {
    pub fn language<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Language(e.into())
    }

    pub fn language_with(msg: impl Into<String>) -> Self {
        Self::Language(anyhow::Error::msg(msg.into()))
    }

    pub fn parse<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Parse(e.into())
    }

    pub fn parse_with(msg: impl Into<String>) -> Self {
        Self::Parse(anyhow::Error::msg(msg.into()))
    }
}

pub struct SourceLanguage {
    language: Language,
    node_types: NodeTypes<'static>,
}

impl SourceLanguage {
    pub fn new(
        language: Language,
        node_types: &'static str,
    ) -> Result<Self, SourceCodeError> {
        Ok(Self {
            language,
            node_types: NodeTypes::new(node_types).map_err(SourceCodeError::language)?,
        })
    }

    pub fn grammar(&self) -> &NodeTypes<'static> {
        &self.node_types
    }
}

pub struct SourceCode<'a> {
    language: &'a SourceLanguage,
    parsed: Tree,
    source: Cow<'a, str>,
}

impl<'a> SourceCode<'a> {
    pub fn new(
        language: &'a SourceLanguage,
        source: impl Into<Cow<'a, str>>,
    ) -> Result<Self, SourceCodeError> {
        let source = source.into();
        let mut parser = Parser::new();

        parser
            .set_language(&language.language)
            .map_err(SourceCodeError::parse)?;

        Ok(Self {
            language,
            parsed: parser
                .parse(source.as_ref(), None)
                .ok_or_else(|| SourceCodeError::parse_with("failed to parse input source code"))?,
            source,
        })
    }

    pub fn language(&self) -> &'a SourceLanguage {
        self.language
    }

    pub fn source(&self) -> &str {
        &*self.source
    }

    pub fn parsed(&self) -> &Tree {
        &self.parsed
    }

    pub fn root<'node, 'lua, 'scope>(
        &'node self,
        scope: &'scope Scope<'lua, 'scope>,
    ) -> NodeRef<'node, 'lua, 'scope>
    where
        'node: 'scope,
        'lua: 'scope,
    {
        NodeRef::new(self.parsed.root_node(), self.source.as_ref(), scope)
    }
}

impl<'a> UserData for SourceCode<'a> {
    fn add_fields<F: UserDataFields<Self>>(_fields: &mut F) {}
    fn add_methods<M: UserDataMethods<Self>>(_methods: &mut M) {}
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_c() -> Result<(), Box<dyn std::error::Error>> {
        let _language = SourceLanguage::new(
            extract::c::language::LANGUAGE.into(),
            extract::c::language::NODE_TYPES,
        )?;
        Ok(())
    }
}
