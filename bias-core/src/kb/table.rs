use std::borrow::Borrow;
use std::hash::Hash;
use std::marker::PhantomData;
use std::mem::{self, transmute, transmute_copy, MaybeUninit};
use std::ops::{Index, IndexMut};
use std::ptr;

use ahash::AHashMap;
use slab::Slab;

use crate::kb::id::{Identifiable, MKey};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MTable<V: Identifiable>
where
    V::Key: MKey,
{
    values: Slab<V>,
}

impl<V> Default for MTable<V>
where
    V: Identifiable,
    V::Key: MKey,
{
    fn default() -> Self {
        Self {
            values: Slab::default(),
        }
    }
}

impl<V> From<Slab<V>> for MTable<V>
where
    V: Identifiable,
    V::Key: MKey,
{
    fn from(values: Slab<V>) -> Self {
        Self { values }
    }
}

impl<V> MTable<V>
where
    V: Identifiable,
    V::Key: MKey,
{
    pub fn reserve(&mut self, n: usize) {
        self.values.reserve(n);
    }

    pub fn insert<F>(&mut self, f: F) -> V::Key
    where
        F: FnOnce(V::Key) -> V,
    {
        let ent = self.values.vacant_entry();
        let id = V::Key::from_index(ent.key());
        ent.insert(f(id));
        id
    }

    pub fn contains(&self, id: V::Key) -> bool {
        self.values.contains(id.index())
    }

    pub fn get(&self, id: V::Key) -> Option<&V> {
        self.values.get(id.index())
    }

    pub fn get_mut(&mut self, id: V::Key) -> Option<&mut V> {
        self.values.get_mut(id.index())
    }

    pub fn get_disjoint_mut<const N: usize>(&mut self, ids: [V::Key; N]) -> Option<[&mut V; N]> {
        if N > 1 {
            // Attempt to make the disjointness check as fast as we can,
            // without using the internals of Slab, or allocating a set.
            //
            // Complexity should be around Nlog(N) + N.

            let mut sorted = ids;
            sorted.sort();

            let mut i = 0;
            while i < (N - 1) {
                if sorted[i] == sorted[i + 1] {
                    return None;
                }
                i += 1;
            }
        }

        // NOTE: replace with MaybeUninit::uninit_array when stable
        let mut values: [MaybeUninit<*mut V>; N] =
            unsafe { MaybeUninit::<[MaybeUninit<*mut V>; N]>::uninit().assume_init() };

        let mut i = 0;
        while i < N {
            let ptr = self.values.get_mut(ids[i].index())? as *mut _;
            values[i].write(ptr);
            i += 1;
        }

        // NOTE: replace with MaybeUninit::array_assume_init when stable
        Some(unsafe { transmute_copy::<_, [&mut V; N]>(&values) })
    }

    pub fn try_get_disjoint_mut(&mut self, ids: &[V::Key]) -> Option<Vec<&mut V>> {
        if ids.len() > 1 {
            // Attempt to make the disjointness check as fast as we can,
            // without using the internals of Slab, or allocating a set.
            //
            // Complexity should be around Nlog(N) + N.

            let mut sorted = ids.to_vec();
            sorted.sort();

            let mut i = 0;
            while i < (sorted.len() - 1) {
                if sorted[i] == sorted[i + 1] {
                    return None;
                }
                i += 1;
            }
        }

        // NOTE: replace with MaybeUninit::uninit_array when stable
        let mut values: Vec<MaybeUninit<*mut V>> = vec![MaybeUninit::<*mut V>::uninit(); ids.len()];

        let mut i = 0;
        while i < values.len() {
            let ptr = self.values.get_mut(ids[i].index())? as *mut _;
            values[i].write(ptr);
            i += 1;
        }

        // NOTE: replace with MaybeUninit::array_assume_init when stable
        Some(unsafe { transmute::<_, Vec<&mut V>>(values) })
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &V> {
        self.values.iter().map(|(_, v)| v)
    }

    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut V> {
        self.values.iter_mut().map(|(_, v)| v)
    }

    pub fn remove(&mut self, id: V::Key) -> Option<V> {
        self.values.try_remove(id.index())
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MPointTable<K: Eq + Hash, V: Identifiable>
where
    V::Key: MKey,
{
    points: AHashMap<K, V::Key>,
    values: MTable<V>,
}

impl<K, V> Default for MPointTable<K, V>
where
    K: Eq + Hash,
    V: Identifiable,
    V::Key: MKey,
{
    fn default() -> Self {
        MPointTable {
            points: AHashMap::default(),
            values: MTable::default(),
        }
    }
}

impl<K, V> MPointTable<K, V>
where
    K: Eq + Hash,
    V: Default + Identifiable,
    V::Key: MKey,
{
    pub fn reserve_points<I>(&mut self, points: I)
    where
        I: ExactSizeIterator<Item = K>,
    {
        self.reserve(points.len());
        points.for_each(|point| {
            self.insert(point, |key| {
                let mut value = V::default();
                *value.id_mut() = key;
                value
            });
        });
    }

    pub fn reserve_points_with<I, F>(&mut self, points: I, mut f: F)
    where
        I: ExactSizeIterator<Item = K>,
        F: FnMut(&K, &mut V),
    {
        self.reserve(points.len());
        points.for_each(|point| {
            self.insert_with(point, |point, key| {
                let mut value = V::default();
                *value.id_mut() = key;
                f(point, &mut value);
                value
            });
        });
    }
}

impl<K, V> MPointTable<K, V>
where
    K: Eq + Hash,
    V: Identifiable,
    V::Key: MKey,
{
    pub(crate) fn from_parts(points: AHashMap<K, V::Key>, values: impl Into<MTable<V>>) -> Self {
        Self {
            points,
            values: values.into(),
        }
    }

    pub(crate) fn parts(&self) -> (&AHashMap<K, V::Key>, &Slab<V>) {
        (&self.points, &self.values.values)
    }

    pub fn reserve(&mut self, n: usize) {
        self.points.reserve(n);
        self.values.values.reserve(n);
    }

    pub fn insert<F>(&mut self, point: K, f: F) -> V::Key
    where
        F: FnOnce(V::Key) -> V,
    {
        let k = self.values.insert(f);
        self.points.insert(point, k);
        k
    }

    pub fn insert_with<F>(&mut self, point: K, f: F) -> V::Key
    where
        F: FnOnce(&K, V::Key) -> V,
    {
        let k = self.values.insert(|k| f(&point, k));
        self.points.insert(point, k);
        k
    }

    pub fn update_point(&mut self, opoint: K, npoint: K) {
        use std::collections::hash_map::Entry;

        if let Some(id) = self.points.remove(&opoint) {
            let entry = self.points.entry(npoint);

            assert!(matches!(entry, Entry::Vacant(_)));

            entry.or_insert(id);
        }
    }

    pub fn contains(&self, id: V::Key) -> bool {
        self.values.contains(id)
    }

    pub fn contains_point<P>(&self, point: P) -> bool
    where
        P: Borrow<K>,
    {
        self.points.contains_key(point.borrow())
    }

    pub fn id<P>(&self, point: P) -> Option<V::Key>
    where
        P: Borrow<K>,
    {
        self.points.get(point.borrow()).copied()
    }

    pub fn get(&self, id: V::Key) -> Option<&V> {
        self.values.get(id)
    }

    pub fn get_point<P>(&self, point: P) -> Option<&V>
    where
        P: Borrow<K>,
    {
        self.points
            .get(point.borrow())
            .and_then(|id| self.values.get(*id))
    }

    pub fn get_mut(&mut self, id: V::Key) -> Option<&mut V> {
        self.values.get_mut(id)
    }

    pub fn get_point_mut<P>(&mut self, point: P) -> Option<&mut V>
    where
        P: Borrow<K>,
    {
        self.points
            .get(point.borrow())
            .and_then(|id| self.values.get_mut(*id))
    }

    pub fn get_disjoint_mut<const N: usize>(&mut self, ids: [V::Key; N]) -> Option<[&mut V; N]> {
        self.values.get_disjoint_mut(ids)
    }

    pub fn try_get_disjoint_mut(&mut self, ids: &[V::Key]) -> Option<Vec<&mut V>> {
        self.values.try_get_disjoint_mut(ids)
    }

    pub fn get_disjoint_points_mut<P, const N: usize>(
        &mut self,
        points: [P; N],
    ) -> Option<[&mut V; N]>
    where
        P: Borrow<K>,
    {
        // NOTE: replace with MaybeUninit::uninit_array when stable
        let mut maybe_ids: [MaybeUninit<V::Key>; N] =
            unsafe { MaybeUninit::<[MaybeUninit<V::Key>; N]>::uninit().assume_init() };

        // LEAKS on failure: V::Key is Copy---no need for Drop.
        for (id, point) in maybe_ids.iter_mut().zip(points.iter()) {
            id.write(*self.points.get(point.borrow())?);
        }

        // NOTE: replace with MaybeUninit::array_assume_init when stable
        let ids = unsafe { (&maybe_ids as *const _ as *const [V::Key; N]).read() };

        self.get_disjoint_mut(ids)
    }

    pub fn values(&self) -> impl ExactSizeIterator<Item = &V> {
        self.values.iter()
    }

    pub fn values_mut(&mut self) -> impl ExactSizeIterator<Item = &mut V> {
        self.values.iter_mut()
    }

    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&K, &V),
    {
        for (p, k) in self.points.iter() {
            let v = self.values.get(*k).unwrap();
            f(p, v);
        }
    }

    pub fn for_each_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &mut V),
    {
        for (p, k) in self.points.iter() {
            let v = self.values.get_mut(*k).unwrap();
            f(p, v);
        }
    }

    pub fn for_each_update_mut<U, F, G>(&mut self, mut f: F, mut g: G)
    where
        F: FnMut(&K, &mut V) -> U,
        G: FnMut(&mut MTable<V>, U) -> U,
    {
        for (p, k) in self.points.iter() {
            let v = self.values.get_mut(*k).unwrap();
            let u = f(p, v);
            g(&mut self.values, u);
        }
    }

    pub fn map<U, F>(mut self, mut f: F) -> MPointTable<K, U>
    where
        U: Identifiable<Key = V::Key>,
        F: FnMut(V::Key, V) -> U,
    {
        let mut points = AHashMap::with_capacity(self.points.capacity());
        let values = Slab::from_iter(self.points.drain().map(|(k, vid)| {
            let v = self.values.values.remove(vid.index());
            let u = f(vid, v);
            points.insert(k, vid);
            (vid.index(), u)
        }))
        .into();

        MPointTable { points, values }
    }

    pub fn filter_map<U, F>(mut self, mut f: F) -> MPointTable<K, U>
    where
        U: Identifiable<Key = V::Key>,
        F: FnMut(V::Key, V) -> Option<U>,
    {
        let mut points = AHashMap::with_capacity(self.points.capacity());
        let values = Slab::from_iter(self.points.drain().filter_map(|(k, vid)| {
            let v = self.values.values.remove(vid.index());
            if let Some(u) = f(vid, v) {
                points.insert(k, vid);
                Some((vid.index(), u))
            } else {
                None
            }
        }))
        .into();

        MPointTable { points, values }
    }

    pub fn remove_point<P>(&mut self, point: P) -> Option<V>
    where
        P: Borrow<K>,
    {
        let id = self.points.remove(point.borrow())?;
        self.values.remove(id)
    }

    pub fn len(&self) -> usize {
        self.points.len()
    }
}

impl<K, V> Index<V::Key> for MPointTable<K, V>
where
    K: Eq + Hash,
    V: Identifiable,
    V::Key: MKey,
{
    type Output = V;

    fn index(&self, id: V::Key) -> &Self::Output {
        self.get(id).unwrap()
    }
}

impl<K, V> IndexMut<V::Key> for MPointTable<K, V>
where
    K: Eq + Hash,
    V: Identifiable,
    V::Key: MKey,
{
    fn index_mut(&mut self, id: V::Key) -> &mut Self::Output {
        self.get_mut(id).unwrap()
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct UPointTable<K: Eq + Hash, V: Identifiable>
where
    V::Key: MKey,
{
    points: AHashMap<K, V::Key>,
    values: Vec<V>,
}

impl<K, V> Default for UPointTable<K, V>
where
    K: Eq + Hash,
    V: Identifiable,
    V::Key: MKey,
{
    fn default() -> Self {
        UPointTable {
            points: AHashMap::default(),
            values: Vec::default(),
        }
    }
}

impl<K, V> UPointTable<K, V>
where
    K: Eq + Hash,
    V: Default + Identifiable,
    V::Key: MKey,
{
    pub fn reserve_points<I>(&mut self, points: I)
    where
        I: ExactSizeIterator<Item = K>,
    {
        self.reserve(points.len());
        points.for_each(|point| {
            self.insert(point, |key| {
                let mut value = V::default();
                *value.id_mut() = key;
                value
            });
        });
    }

    pub fn reserve_points_with<I, F>(&mut self, points: I, mut f: F)
    where
        I: ExactSizeIterator<Item = K>,
        F: FnMut(&K, &mut V),
    {
        self.reserve(points.len());
        points.for_each(|point| {
            self.insert_with(point, |point, key| {
                let mut value = V::default();
                *value.id_mut() = key;
                f(point, &mut value);
                value
            });
        });
    }
}

impl<K, V> UPointTable<K, V>
where
    K: Eq + Hash,
    V: Identifiable,
    V::Key: MKey,
{
    pub fn reserve(&mut self, n: usize) {
        self.points.reserve(n);
        self.values.reserve(n);
    }

    pub fn insert<F>(&mut self, point: K, f: F) -> V::Key
    where
        F: FnOnce(V::Key) -> V,
    {
        let k = MKey::from_index(self.values.len());
        self.values.push(f(k));
        self.points.insert(point, k);
        k
    }

    pub fn insert_with<F>(&mut self, point: K, f: F) -> V::Key
    where
        F: FnOnce(&K, V::Key) -> V,
    {
        let k = MKey::from_index(self.values.len());
        self.values.push(f(&point, k));
        self.points.insert(point, k);
        k
    }

    pub fn contains(&self, id: V::Key) -> bool {
        self.values.len() > id.index()
    }

    pub fn contains_point<P>(&self, point: P) -> bool
    where
        P: Borrow<K>,
    {
        self.points.contains_key(point.borrow())
    }

    pub fn id<P>(&self, point: P) -> Option<V::Key>
    where
        P: Borrow<K>,
    {
        self.points.get(point.borrow()).copied()
    }

    pub fn get(&self, id: V::Key) -> Option<&V> {
        self.values.get(id.index())
    }

    pub fn get_point<P>(&self, point: P) -> Option<&V>
    where
        P: Borrow<K>,
    {
        self.points
            .get(point.borrow())
            .and_then(|id| self.values.get(id.index()))
    }

    pub fn get_mut(&mut self, id: V::Key) -> Option<&mut V> {
        self.values.get_mut(id.index())
    }

    pub fn get_point_mut<P>(&mut self, point: P) -> Option<&mut V>
    where
        P: Borrow<K>,
    {
        self.points
            .get(point.borrow())
            .and_then(|id| self.values.get_mut(id.index()))
    }

    pub fn get_point_full_mut<P>(&mut self, point: P) -> Option<(V::Key, &mut V)>
    where
        P: Borrow<K>,
    {
        self.points
            .get(point.borrow())
            .and_then(|id| self.values.get_mut(id.index()).map(|v| (*id, v)))
    }

    pub fn values(&self) -> impl ExactSizeIterator<Item = &V> {
        self.values.iter()
    }

    pub fn values_mut(&mut self) -> impl ExactSizeIterator<Item = &mut V> {
        self.values.iter_mut()
    }

    pub fn into_values(self) -> impl ExactSizeIterator<Item = V> {
        self.values.into_iter()
    }

    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&K, &V),
    {
        for (p, k) in self.points.iter() {
            let v = self.values.get(k.index()).unwrap();
            f(p, v);
        }
    }

    pub fn for_each_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &mut V),
    {
        for (p, k) in self.points.iter() {
            let v = self.values.get_mut(k.index()).unwrap();
            f(p, v);
        }
    }

    pub fn for_each_update_mut<U, F, G>(&mut self, mut f: F, mut g: G)
    where
        F: FnMut(&K, &mut V) -> U,
        G: FnMut(&mut Vec<V>, U) -> U,
    {
        for (p, k) in self.points.iter() {
            let v = self.values.get_mut(k.index()).unwrap();
            let u = f(p, v);
            g(&mut self.values, u);
        }
    }

    pub(crate) fn from_parts(points: AHashMap<K, V::Key>, values: Vec<V>) -> Self {
        Self { points, values }
    }

    pub(crate) fn parts(&self) -> (&AHashMap<K, V::Key>, &Vec<V>) {
        (&self.points, &self.values)
    }

    // NOTE: this is derived from Rust 1.3.x (https://github.com/rust-lang/rust/blob/1.3.0/src/libcollections/vec.rs#L787-L961)
    pub fn map_in_place<U, F>(self, mut f: F) -> UPointTable<K, U>
    where
        F: FnMut(V) -> U,
        U: Identifiable<Key = V::Key>,
    {
        // FIXME: Assert statically that the types `T` and `U` have the same
        // size.
        assert!(mem::size_of::<V>() == mem::size_of::<U>());

        let mut vec = self.values;

        if mem::size_of::<V>() != 0 {
            // FIXME: Assert statically that the types `T` and `U` have the
            // same minimal alignment in case they are not zero-sized.

            // These asserts are necessary because the `align_of` of the
            // types are passed to the allocator by `Vec`.
            assert!(mem::align_of::<V>() == mem::align_of::<U>());

            // This `as isize` cast is safe, because the size of the elements of the
            // vector is not 0, and:
            //
            // 1) If the size of the elements in the vector is 1, the `isize` may
            //    overflow, but it has the correct bit pattern so that the
            //    `.offset()` function will work.
            //
            //    Example:
            //        Address space 0x0-0xF.
            //        `u8` array at: 0x1.
            //        Size of `u8` array: 0x8.
            //        Calculated `offset`: -0x8.
            //        After `array.offset(offset)`: 0x9.
            //        (0x1 + 0x8 = 0x1 - 0x8)
            //
            // 2) If the size of the elements in the vector is >1, the `usize` ->
            //    `isize` conversion can't overflow.
            let offset = vec.len() as isize;
            let start = vec.as_mut_ptr();

            let mut pv = PartialVecNonZeroSized {
                vec,

                start_t: start,
                // This points inside the vector, as the vector has length
                // `offset`.
                end_t: unsafe { start.offset(offset) },
                start_u: start as *mut U,
                end_u: start as *mut U,

                _marker: PhantomData,
            };
            //  start_t
            //  start_u
            //  |
            // +-+-+-+-+-+-+
            // |T|T|T|...|T|
            // +-+-+-+-+-+-+
            //  |           |
            //  end_u       end_t

            while pv.end_u as *mut V != pv.end_t {
                unsafe {
                    //  start_u start_t
                    //  |       |
                    // +-+-+-+-+-+-+-+-+-+
                    // |U|...|U|T|T|...|T|
                    // +-+-+-+-+-+-+-+-+-+
                    //          |         |
                    //          end_u     end_t

                    let t = ptr::read(pv.start_t);
                    //  start_u start_t
                    //  |       |
                    // +-+-+-+-+-+-+-+-+-+
                    // |U|...|U|X|T|...|T|
                    // +-+-+-+-+-+-+-+-+-+
                    //          |         |
                    //          end_u     end_t
                    // We must not panic here, one cell is marked as `T`
                    // although it is not `T`.

                    pv.start_t = pv.start_t.offset(1);
                    //  start_u   start_t
                    //  |         |
                    // +-+-+-+-+-+-+-+-+-+
                    // |U|...|U|X|T|...|T|
                    // +-+-+-+-+-+-+-+-+-+
                    //          |         |
                    //          end_u     end_t
                    // We may panic again.

                    // The function given by the user might panic.
                    let u = f(t);

                    ptr::write(pv.end_u, u);
                    //  start_u   start_t
                    //  |         |
                    // +-+-+-+-+-+-+-+-+-+
                    // |U|...|U|U|T|...|T|
                    // +-+-+-+-+-+-+-+-+-+
                    //          |         |
                    //          end_u     end_t
                    // We should not panic here, because that would leak the `U`
                    // pointed to by `end_u`.

                    pv.end_u = pv.end_u.offset(1);
                    //  start_u   start_t
                    //  |         |
                    // +-+-+-+-+-+-+-+-+-+
                    // |U|...|U|U|T|...|T|
                    // +-+-+-+-+-+-+-+-+-+
                    //            |       |
                    //            end_u   end_t
                    // We may panic again.
                }
            }

            //  start_u     start_t
            //  |           |
            // +-+-+-+-+-+-+
            // |U|...|U|U|U|
            // +-+-+-+-+-+-+
            //              |
            //              end_t
            //              end_u
            // Extract `vec` and prevent the destructor of
            // `PartialVecNonZeroSized` from running. Note that none of the
            // function calls can panic, thus no resources can be leaked (as the
            // `vec` member of `PartialVec` is the only one which holds
            // allocations -- and it is returned from this function. None of
            // this can panic.
            let result = unsafe {
                let vec_len = pv.vec.len();
                let vec_cap = pv.vec.capacity();
                let vec_ptr = pv.vec.as_mut_ptr() as *mut U;
                mem::forget(pv);
                Vec::from_raw_parts(vec_ptr, vec_len, vec_cap)
            };

            UPointTable {
                values: result,
                points: self.points,
            }
        } else {
            // Put the `Vec` into the `PartialVecZeroSized` structure and
            // prevent the destructor of the `Vec` from running. Since the
            // `Vec` contained zero-sized objects, it did not allocate, so we
            // are not leaking memory here.
            let mut pv = PartialVecZeroSized::<V, U> {
                num_t: vec.len(),
                num_u: 0,
                marker: PhantomData,
            };
            mem::forget(vec);

            while pv.num_t != 0 {
                unsafe {
                    // Create a `T` out of thin air and decrement `num_t`. This
                    // must not panic between these steps, as otherwise a
                    // destructor of `T` which doesn't exist runs.
                    let t = mem::MaybeUninit::uninit().assume_init();
                    pv.num_t -= 1;

                    // The function given by the user might panic.
                    let u = f(t);

                    // Forget the `U` and increment `num_u`. This increment
                    // cannot overflow the `usize` as we only do this for a
                    // number of times that fits into a `usize` (and start with
                    // `0`). Again, we should not panic between these steps.
                    mem::forget(u);
                    pv.num_u += 1;
                }
            }
            // Create a `Vec` from our `PartialVecZeroSized` and make sure the
            // destructor of the latter will not run. None of this can panic.
            let mut result = Vec::new();
            unsafe {
                result.set_len(pv.num_u);
                mem::forget(pv);
            }

            UPointTable {
                values: result,
                points: self.points,
            }
        }
    }

    pub fn len(&self) -> usize {
        self.points.len()
    }
}

impl<K, V> Index<V::Key> for UPointTable<K, V>
where
    K: Eq + Hash,
    V: Identifiable,
    V::Key: MKey,
{
    type Output = V;

    fn index(&self, id: V::Key) -> &Self::Output {
        self.get(id).unwrap()
    }
}

impl<K, V> IndexMut<V::Key> for UPointTable<K, V>
where
    K: Eq + Hash,
    V: Identifiable,
    V::Key: MKey,
{
    fn index_mut(&mut self, id: V::Key) -> &mut Self::Output {
        self.get_mut(id).unwrap()
    }
}

////////////////////////////////////////////////////////////////////////////////
// Partial vec, used for map_in_place
////////////////////////////////////////////////////////////////////////////////

/// An owned, partially type-converted vector of elements with non-zero size.
///
/// `T` and `U` must have the same, non-zero size. They must also have the same
/// alignment.
///
/// When the destructor of this struct runs, all `U`s from `start_u` (incl.) to
/// `end_u` (excl.) and all `T`s from `start_t` (incl.) to `end_t` (excl.) are
/// destructed. Additionally the underlying storage of `vec` will be freed.
struct PartialVecNonZeroSized<T, U> {
    vec: Vec<T>,

    start_u: *mut U,
    end_u: *mut U,
    start_t: *mut T,
    end_t: *mut T,

    _marker: PhantomData<U>,
}

/// An owned, partially type-converted vector of zero-sized elements.
///
/// When the destructor of this struct runs, all `num_t` `T`s and `num_u` `U`s
/// are destructed.
struct PartialVecZeroSized<T, U> {
    num_t: usize,
    num_u: usize,
    marker: PhantomData<::core::cell::Cell<(T, U)>>,
}

impl<T, U> Drop for PartialVecNonZeroSized<T, U> {
    fn drop(&mut self) {
        unsafe {
            // `vec` hasn't been modified until now. As it has a length
            // currently, this would run destructors of `T`s which might not be
            // there. So at first, set `vec`s length to `0`. This must be done
            // at first to remain memory-safe as the destructors of `U` or `T`
            // might cause unwinding where `vec`s destructor would be executed.
            self.vec.set_len(0);

            // We have instances of `U`s and `T`s in `vec`. Destruct them.
            while self.start_u != self.end_u {
                let _ = ptr::read(self.start_u); // Run a `U` destructor.
                self.start_u = self.start_u.offset(1);
            }
            while self.start_t != self.end_t {
                let _ = ptr::read(self.start_t); // Run a `T` destructor.
                self.start_t = self.start_t.offset(1);
            }
            // After this destructor ran, the destructor of `vec` will run,
            // deallocating the underlying memory.
        }
    }
}

impl<T, U> Drop for PartialVecZeroSized<T, U> {
    fn drop(&mut self) {
        unsafe {
            // Destruct the instances of `T` and `U` this struct owns.
            while self.num_t != 0 {
                let _: T = mem::MaybeUninit::uninit().assume_init(); // Run a `T` destructor.
                self.num_t -= 1;
            }
            while self.num_u != 0 {
                let _: U = mem::MaybeUninit::uninit().assume_init(); // Run a `U` destructor.
                self.num_u -= 1;
            }
        }
    }
}
