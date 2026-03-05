use std::borrow::Cow;
use serde_json::Error;

use bias_core::kb::{AHashMap, AHashSet};

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Node<'a> {
    #[serde(rename(deserialize = "type", serialize = "type"))]
    ty: Cow<'a, str>,
    named: bool,
    #[serde(default, borrow)]
    children: Children<'a>,
    #[serde(default)]
    fields: AHashMap<Cow<'a, str>, Field<'a>>,
    #[serde(default)]
    subtypes: Vec<Subtype<'a>>,
}

#[derive(Clone, Debug, Default, Hash, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct Children<'a> {
    multiple: bool,
    required: bool,
    #[serde(borrow)]
    types: Vec<Subtype<'a>>,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Field<'a> {
    pub multiple: bool,
    pub required: bool,
    #[serde(borrow)]
    pub types: Vec<Subtype<'a>>,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Subtype<'a> {
    #[serde(rename(deserialize = "type", serialize = "type"))]
    pub ty: Cow<'a, str>,
    pub named: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeTypes<'a> {
    parents: AHashMap<Cow<'a, str>, AHashSet<Cow<'a, str>>>,
    children: AHashMap<Cow<'a, str>, AHashSet<Cow<'a, str>>>,
}

impl<'a> NodeTypes<'a> {
    pub fn new(node_types_json_str: &'a str) -> Result<Self, Error> {
        let nodes: Vec<Node> = serde_json::from_str(node_types_json_str)?;
        let mut parents = AHashMap::with_capacity(nodes.len());
        let mut children = AHashMap::with_capacity(nodes.len());
        for node in nodes {
            let mut subs = AHashSet::with_capacity(node.subtypes.len());
            for sub in node.subtypes.into_iter() {
                parents
                    .entry(sub.ty.clone())
                    .or_insert_with(AHashSet::new)
                    .insert(node.ty.clone());
                subs.insert(sub.ty);
            }
            children.insert(node.ty, subs);
        }
        Ok(NodeTypes { parents, children })
    }

    pub fn is_child_of(&self, child: &str, parent: &str) -> bool {
        self.children
            .get(parent)
            .map_or(false, |cs| cs.contains(child))
    }

    pub fn is_descendant_of(&self, desc: &str, ansc: &str) -> bool {
        ansc == desc
            || self.children.get(ansc).map_or(false, |cs| {
                cs.contains(desc) || cs.iter().any(|c| self.is_descendant_of(desc, c))
            })
    }

    pub fn is_parent_of(&self, parent: &str, child: &str) -> bool {
        self.parents
            .get(child)
            .map_or(false, |ps| ps.contains(parent))
    }

    pub fn is_ancestor_of(&self, ansc: &str, desc: &str) -> bool {
        ansc == desc
            || self.children.get(ansc).map_or(false, |cs| {
                cs.contains(desc) || cs.iter().any(|c| self.is_descendant_of(c, desc))
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_node_types() {
        let nt = NodeTypes::new(crate::lua::source::extract::c::language::NODE_TYPES).unwrap();

        assert!(nt.is_child_of("function_declarator", "_declarator"));
        assert!(nt.is_descendant_of("function_declarator", "_declarator"));
        assert!(nt.is_parent_of("_declarator", "function_declarator"));
        assert!(!nt.is_child_of("_declarator", "identifier"));
    }
}
