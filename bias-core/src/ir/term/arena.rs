use std::borrow::{Borrow, Cow};
use std::cmp::Ordering;
use std::fmt::{self, Debug, Display};
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};

pub use shared_arena;
pub use shared_arena::{Arena, ArenaArc, ArenaBox, Block};

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Term<T> {
    pub val: ArenaArc<T>,
}

pub type RawTerm<T> = Block<T>;

#[macro_export]
macro_rules! impl_term_mut {
    ($arena:tt for $t:tt) => {
        impl AsMut<$t> for Term<$t> {
            fn as_mut(&mut self) -> &mut $t {
                $arena
                    .with(|arena| $crate::ir::term::arena::ArenaArc::make_mut(arena, &mut self.val))
            }
        }

        impl ::std::borrow::BorrowMut<$t> for Term<$t> {
            fn borrow_mut(&mut self) -> &mut $t {
                $arena
                    .with(|arena| $crate::ir::term::arena::ArenaArc::make_mut(arena, &mut self.val))
            }
        }

        impl ::std::ops::DerefMut for Term<$t> {
            fn deref_mut(&mut self) -> &mut $t {
                $arena
                    .with(|arena| $crate::ir::term::arena::ArenaArc::make_mut(arena, &mut self.val))
            }
        }
    };
}

/*
impl<T> Clone for Term<T> where T: Clone + Into<Term<T>> {
    fn clone(&self) -> Self {
        self.val.clone().into()
    }
}
*/

impl<T> AsRef<T> for Term<T> {
    fn as_ref(&self) -> &T {
        &*self.val
    }
}

/*
impl<T> AsMut<T> for Term<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.val
    }
}
*/

impl<T> Borrow<T> for Term<T> {
    fn borrow(&self) -> &T {
        &*self.val
    }
}

/*
impl<T> BorrowMut<T> for Term<T> {
    fn borrow_mut(&mut self) -> &mut T {
        &mut *self.val
    }
}
*/

impl<T> Deref for Term<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &*self.val
    }
}

/*
impl<T> DerefMut for Term<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.val
    }
}
*/

impl<T> Display for Term<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.val.fmt(f)
    }
}

impl<T> PartialEq for Term<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        *self.val == *other.val
    }
}
impl<T> Eq for Term<T> where T: PartialEq {}

impl<T> PartialOrd for Term<T>
where
    T: PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.val.partial_cmp(&other.val)
    }
}

impl<T> Ord for Term<T>
where
    T: Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.val.cmp(&other.val)
    }
}

impl<T> Hash for Term<T>
where
    T: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.val.hash(state)
    }
}

impl<T> Term<T>
where
    T: Clone,
{
    pub fn new(irb: &Arena<T>, val: T) -> Self {
        Self {
            val: irb.alloc_arc(val),
        }
    }

    #[inline(always)]
    pub fn update_with<F>(&mut self, irb: &Arena<T>, f: F)
    where
        F: FnOnce(&Arena<T>, &mut Cow<T>),
    {
        let mut nval = Cow::Borrowed(&*self.val);
        f(irb, &mut nval);
        if let Cow::Owned(val) = nval {
            self.val = irb.alloc_arc(val);
        }
    }

    #[inline(always)]
    pub unsafe fn from_raw(ptr: *mut RawTerm<T>) -> Option<Term<T>> {
        ArenaArc::from_raw(ptr).map(|val| Term { val })
    }

    #[inline(always)]
    pub fn into_raw(self) -> *mut RawTerm<T> {
        self.val.into_raw()
    }

    #[inline(always)]
    pub fn value(&self) -> &T {
        &*self.val
    }
}

impl<T> Term<T>
where
    T: Clone,
    Term<T>: DerefMut<Target = T>,
{
    #[inline(always)]
    pub fn to_mut(&mut self) -> &mut T {
        self.deref_mut()
    }
}

impl<T> serde::Serialize for Term<T>
where
    T: serde::Serialize + Clone + Hash,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.value().serialize(serializer)
    }
}

impl<'de, T> serde::Deserialize<'de> for Term<T>
where
    T: serde::Deserialize<'de> + Into<Term<T>> + Clone + Hash,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(T::deserialize(deserializer)?.into())
    }
}

pub trait TermMut<T>
where
    T: Clone + Hash,
{
    fn update<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Cow<T>);

    fn set(&mut self, v: T) {
        self.update(|ov| *ov = Cow::Owned(v))
    }
}
