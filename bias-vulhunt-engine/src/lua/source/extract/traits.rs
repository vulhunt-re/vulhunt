use tree_sitter::{Language, Node, TreeCursor};

pub trait EntityExtractor<'t> {
    const NODE: &'static str;
    const NAMED: bool = true;
    const FIELDS: &'static [&'static str] = &[];

    // match config.
    const EXTRACT_WITHIN_MATCHES: bool = false;

    type Target;

    fn extract<'a>(&self, node: Node<'a>, walker: &mut TreeCursor<'a>, source: &'a str) -> Option<Self::Target>;
    fn language(&self) -> Language;
}
