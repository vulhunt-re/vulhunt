use std::mem;

use mlua::{AnyUserData, Error, Lua, Scope, UserData, UserDataMethods};

use super::extract::languages::Node;

#[derive(Clone)]
pub struct NodeRef<'node, 'lua, 'scope>
where
    'node: 'scope,
    'lua: 'scope,
{
    node: Node<'node>,
    text: &'node str,
    scope: &'scope Scope<'lua, 'scope>,
}

impl<'node, 'lua, 'scope> NodeRef<'node, 'lua, 'scope>
where
    'node: 'scope,
    'lua: 'scope,
{
    pub fn new(node: Node<'node>, text: &'node str, scope: &'scope Scope<'lua, 'scope>) -> Self {
        Self { node, text, scope }
    }

    pub fn scope(self, _: &Lua) -> Result<AnyUserData, Error> {
        self.scope
            .create_userdata(self)
            .map(|data| unsafe { mem::transmute(data) })
    }

    fn with_node(&self, node: Node<'node>) -> Self {
        Self {
            node,
            text: self.text,
            scope: self.scope,
        }
    }

    fn child(&self, idx: usize) -> Option<Self> {
        self.node.child(idx).map(|n| self.with_node(n))
    }

    fn child_count(&self) -> usize {
        self.node.child_count()
    }

    fn kind(&self) -> &'static str {
        self.node.kind()
    }

    fn next_named_sibling(&self) -> Option<Self> {
        self.node.next_named_sibling().map(|n| self.with_node(n))
    }

    fn next_sibling(&self) -> Option<Self> {
        self.node.next_sibling().map(|n| self.with_node(n))
    }

    fn parent(&self) -> Option<Self> {
        self.node.parent().map(|n| self.with_node(n))
    }

    fn prev_named_sibling(&self) -> Option<Self> {
        self.node.prev_named_sibling().map(|n| self.with_node(n))
    }

    fn prev_sibling(&self) -> Option<Self> {
        self.node.prev_sibling().map(|n| self.with_node(n))
    }

    fn text(&self) -> &str {
        self.node.utf8_text(self.text.as_bytes()).unwrap()
    }
}

impl<'node, 'lua, 'scope> UserData for NodeRef<'node, 'lua, 'scope>
where
    'node: 'scope,
    'lua: 'scope,
{
    fn add_methods<T: UserDataMethods<Self>>(methods: &mut T) {
        methods.add_method("child", |lua, this, i: usize| {
            this.child(i).map(|node| node.scope(lua)).transpose()
        });
        methods.add_method("child_count", |_, this, _: ()| Ok(this.child_count()));
        methods.add_method("kind", |_, this, _: ()| Ok(this.kind()));
        methods.add_method("next_named_sibling", |lua, this, _: ()| {
            this.next_named_sibling()
                .map(|node| node.scope(lua))
                .transpose()
        });
        methods.add_method("next_sibling", |lua, this, _: ()| {
            this.next_sibling().map(|node| node.scope(lua)).transpose()
        });
        methods.add_method("parent", |lua, this, _: ()| {
            this.parent().map(|node| node.scope(lua)).transpose()
        });
        methods.add_method("prev_named_sibling", |lua, this, _: ()| {
            this.prev_named_sibling()
                .map(|node| node.scope(lua))
                .transpose()
        });
        methods.add_method("prev_sibling", |lua, this, _: ()| {
            this.prev_sibling().map(|node| node.scope(lua)).transpose()
        });
        methods.add_method("text", |_, this, _: ()| Ok(this.text().to_owned()));
    }
}
