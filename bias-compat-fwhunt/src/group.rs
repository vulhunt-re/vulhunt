use std::marker::PhantomData;

use bias_core::Project;
use serde::de::{Error, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize};

use crate::matcher::MatchContext;
use crate::traits::MatchesRule;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupKind {
    All,
    Any,
    NotAll,
    NotAny,
}

impl Serialize for GroupKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            Self::All => "and",
            Self::Any => "or",
            Self::NotAll => "not-all",
            Self::NotAny => "not-any",
        };

        serializer.serialize_str(s)
    }
}

impl Default for GroupKind {
    fn default() -> Self {
        GroupKind::All
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Group<T> {
    kind: GroupKind,
    values: Vec<T>,
}

impl<T> Group<T> {
    #[inline]
    pub fn kind(&self) -> GroupKind {
        self.kind
    }

    #[inline]
    pub fn values(&self) -> &[T] {
        &self.values
    }
}

impl<T> MatchesRule for Group<T>
where
    T: MatchesRule,
{
    fn is_group(&self) -> bool {
        true
    }

    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        let checkpoint = context.begin(self);
        let result = match self.kind {
            GroupKind::All => self.values.iter().all(|r| {
                let checkpoint1 = context.begin(r);
                if r.matches_rule(context, project) {
                    context.commit(checkpoint1);
                    true
                } else {
                    context.discard(checkpoint1);
                    false
                }
            }),
            GroupKind::Any => self.values.iter().any(|r| {
                let checkpoint1 = context.begin(r);
                if r.matches_rule(context, project) {
                    context.commit(checkpoint1);
                    true
                } else {
                    context.discard(checkpoint1);
                    false
                }
            }),
            GroupKind::NotAll => !self.values.iter().all(|r| {
                let checkpoint1 = context.begin(r);
                if !r.matches_rule(context, project) {
                    context.commit(checkpoint1);
                    false
                } else {
                    context.discard(checkpoint1);
                    true
                }
            }),
            GroupKind::NotAny => !self.values.iter().any(|r| {
                let checkpoint1 = context.begin(r);
                let result = r.matches_rule(context, project);
                context.discard(checkpoint1);
                result
            }),
        };
        if result {
            context.commit(checkpoint);
        } else {
            context.discard(checkpoint);
        }
        result
    }

    fn matches_bytes(&self, context: &mut MatchContext, bytes: &[u8]) -> bool {
        let checkpoint = context.begin(self);
        let result = match self.kind {
            GroupKind::All => self.values.iter().all(|r| {
                let checkpoint1 = context.begin(r);
                if r.matches_bytes(context, bytes) {
                    context.commit(checkpoint1);
                    true
                } else {
                    context.discard(checkpoint1);
                    false
                }
            }),
            GroupKind::Any => self.values.iter().any(|r| {
                let checkpoint1 = context.begin(r);
                if r.matches_bytes(context, bytes) {
                    context.commit(checkpoint1);
                    true
                } else {
                    context.discard(checkpoint1);
                    false
                }
            }),
            GroupKind::NotAll => !self.values.iter().all(|r| {
                let checkpoint1 = context.begin(r);
                if !r.matches_bytes(context, bytes) {
                    context.commit(checkpoint1);
                    false
                } else {
                    context.discard(checkpoint1);
                    true
                }
            }),
            GroupKind::NotAny => !self.values.iter().any(|r| {
                let checkpoint1 = context.begin(r);
                let result = r.matches_bytes(context, bytes);
                context.discard(checkpoint1);
                result
            }),
        };
        if result {
            context.commit(checkpoint);
        } else {
            context.discard(checkpoint);
        }
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Groups<T>(Vec<Group<T>>);

impl<T> Groups<T> {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Group<T>> {
        self.0.iter()
    }

    fn with_group(mut self, kind: GroupKind, iter: impl IntoIterator<Item = T>) -> Self {
        let values = iter.into_iter().collect::<Vec<_>>();
        if values.is_empty() {
            self
        } else {
            self.0.push(Group { kind, values });
            self
        }
    }

    pub fn and_any_of(self, iter: impl IntoIterator<Item = T>) -> Self {
        self.with_group(GroupKind::Any, iter)
    }

    pub fn and_all_of(self, iter: impl IntoIterator<Item = T>) -> Self {
        self.with_group(GroupKind::All, iter)
    }

    pub fn and_none_of(self, iter: impl IntoIterator<Item = T>) -> Self {
        self.with_group(GroupKind::NotAny, iter)
    }
}

impl<T> MatchesRule for Groups<T>
where
    T: MatchesRule,
{
    fn is_group(&self) -> bool {
        true
    }

    fn matches_rule(&self, context: &mut MatchContext, project: &Project) -> bool {
        let checkpoint = context.begin(self);
        let result = self.0.iter().all(|r| r.matches_rule(context, project));
        if result {
            context.commit(checkpoint);
        } else {
            context.discard(checkpoint);
        }
        result
    }

    fn matches_bytes(&self, context: &mut MatchContext, bytes: &[u8]) -> bool {
        let checkpoint = context.begin(self);
        let result = self.0.iter().all(|r| r.matches_bytes(context, bytes));
        if result {
            context.commit(checkpoint);
        } else {
            context.discard(checkpoint);
        }
        result
    }
}

impl<T> Default for Groups<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

// if GroupKind == "", i.e., the input is a list then treat as And with a flat list of values
// if GroupKind != "" then treat as kind with a sub-list of values

struct GroupVisitor<T>(PhantomData<T>);

impl<T> Default for GroupVisitor<T> {
    fn default() -> Self {
        GroupVisitor(PhantomData)
    }
}

impl<'de, T> Visitor<'de> for GroupVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Groups<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("(optionally) predicated sequence of checks to perform")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let kind = Default::default();
        let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(0));

        while let Some(value) = seq.next_element()? {
            values.push(value);
        }

        Ok(Groups(vec![Group { kind, values }]))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut groups = Vec::with_capacity(map.size_hint().unwrap_or(0));

        loop {
            let kind = match map.next_key::<String>()?.as_deref() {
                Some("and" | "all") => GroupKind::All,
                Some("any" | "or") => GroupKind::Any,
                Some("not-all") => GroupKind::NotAll,
                Some("not-any") => GroupKind::NotAny,
                Some(c) => return Err(Error::custom(format!("unknown grouping operator `{c}`")))?,
                None => break,
            };

            let values = map.next_value::<Vec<T>>()?;

            groups.push(Group { kind, values });
        }

        Ok(Groups(groups))
    }
}

impl<'de, T> Deserialize<'de> for Groups<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(GroupVisitor::default())
    }
}

impl<T> Serialize for Groups<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.len() == 1 && self.0[0].kind() == GroupKind::default() {
            // Serialize as a sequence
            let mut seq = serializer.serialize_seq(Some(self.0[0].values.len()))?;
            for elem in self.0[0].values.iter() {
                seq.serialize_element(elem)?;
            }
            seq.end()
        } else {
            // Serialize as a map
            let mut map = serializer.serialize_map(Some(self.len()))?;
            for group in self.iter() {
                map.serialize_entry(&group.kind(), group.values())?;
            }
            map.end()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_basic_groups() -> Result<(), Box<dyn std::error::Error>> {
        let map1 = r"
- blah
- blah1
- blah2
";
        let map2 = r"
or:
- blah
- blah1
- blah2
";

        let map3 = r"
or:
- blah
- blah1
- blah2
and:
- blah4
";

        let map1_group: Groups<String> = serde_yaml::from_str(map1)?;

        assert_eq!(
            map1_group,
            Groups(vec![Group {
                kind: GroupKind::All,
                values: vec!["blah".to_string(), "blah1".to_string(), "blah2".to_string()],
            }])
        );

        let map2_group: Groups<String> = serde_yaml::from_str(map2)?;

        assert_eq!(
            map2_group,
            Groups(vec![Group {
                kind: GroupKind::Any,
                values: vec!["blah".to_string(), "blah1".to_string(), "blah2".to_string()],
            }])
        );

        let map3_group: Groups<String> = serde_yaml::from_str(map3)?;

        assert_eq!(
            map3_group,
            Groups(vec![
                Group {
                    kind: GroupKind::Any,
                    values: vec!["blah".to_string(), "blah1".to_string(), "blah2".to_string()],
                },
                Group {
                    kind: GroupKind::All,
                    values: vec!["blah4".to_string()],
                },
            ]),
        );

        Ok(())
    }

    #[test]
    fn test_basic_groups_ser() -> Result<(), Box<dyn std::error::Error>> {
        let map1_s = r"
- blah
- blah1
- blah2
";
        let map2_s = r"
or:
  - blah
  - blah1
  - blah2
";

        let map3_s = r"
or:
  - blah
  - blah1
  - blah2
and:
  - blah4
";

        let map1 = Groups(vec![Group {
            kind: GroupKind::All,
            values: vec!["blah".to_string(), "blah1".to_string(), "blah2".to_string()],
        }]);

        let map2 = Groups(vec![Group {
            kind: GroupKind::Any,
            values: vec!["blah".to_string(), "blah1".to_string(), "blah2".to_string()],
        }]);

        let map3 = Groups(vec![
            Group {
                kind: GroupKind::Any,
                values: vec!["blah".to_string(), "blah1".to_string(), "blah2".to_string()],
            },
            Group {
                kind: GroupKind::All,
                values: vec!["blah4".to_string()],
            },
        ]);

        assert_eq!(map1_s.trim(), serde_yaml::to_string(&map1)?.trim());
        assert_eq!(map2_s.trim(), serde_yaml::to_string(&map2)?.trim());
        assert_eq!(map3_s.trim(), serde_yaml::to_string(&map3)?.trim());

        Ok(())
    }
}
