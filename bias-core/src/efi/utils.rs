pub mod btree {
    use std::collections::{BTreeMap, BTreeSet};

    pub fn btreemap_drain<K, V>(map: &mut BTreeMap<K, V>) -> impl Iterator<Item = (K, V)>
    where
        K: Ord,
    {
        std::mem::take(map).into_iter()
    }

    pub fn btreeset_drain<T>(set: &mut BTreeSet<T>) -> impl Iterator<Item = T>
    where
        T: Ord,
    {
        std::mem::take(set).into_iter()
    }

    pub fn btreeset_drain_filter<T, F>(
        set: &mut BTreeSet<T>,
        mut predicate: F,
    ) -> impl Iterator<Item = T>
    where
        T: Ord + Clone,
        F: FnMut(&T) -> bool,
    {
        let filtered = set
            .iter()
            .filter(|item| predicate(item))
            .cloned()
            .collect::<Vec<_>>();

        for item in &filtered {
            set.remove(item);
        }

        filtered.into_iter()
    }
}
