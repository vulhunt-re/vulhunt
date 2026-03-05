use std::collections::VecDeque;
use std::marker::PhantomData;

use crate::kb::id::MKey;

pub enum Outcome<T> {
    Ok,
    PropagateBackward(T),
    PropagateForward(T),
    Stop,
}

pub struct FixedPoint<'a, K, E, P, T>
where
    K: MKey + 'a,
    E: std::error::Error,
    P: 'a,
    T: Pass<'a, K, P, E>,
{
    pass: T,
    work: VecDeque<K>,
    _marker: PhantomData<&'a (K, E, P)>,
}

impl<'a, K, E, P, T> FixedPoint<'a, K, E, P, T>
where
    K: MKey + 'a,
    E: std::error::Error,
    P: 'a,
    T: Pass<'a, K, P, E>
{
    pub fn new(mut pass: T) -> Self {
        Self {
            work: pass.init(),
            pass,
            _marker: PhantomData,
        }
    }

    pub fn run(&mut self) -> Result<(), E> {
        while let Some(next) = self.work.pop_front() {
            match self.pass.process(&next)? {
                Outcome::Ok => continue,
                Outcome::PropagateForward(p) => {
                    self.pass.propagate_forward(next, p, &mut self.work)?;
                }
                Outcome::PropagateBackward(p) => {
                    self.pass.propagate_backward(next, p, &mut self.work)?;
                }
                Outcome::Stop => {
                    return Ok(())
                }
            }
        }
        Ok(())
    }
}

pub trait Pass<'a, K, P, E> where K: MKey + 'a, P: 'a, E: std::error::Error {
    fn init(&mut self) -> VecDeque<K>;
    fn process(&mut self, k: &K) -> Result<Outcome<P>, E>;

    #[allow(unused)]
    fn propagate_backward(&self, k: K, p: P, work: &mut VecDeque<K>) -> Result<(), E> {
        Ok(())
    }

    #[allow(unused)]
    fn propagate_forward(&self, k: K, p: P, work: &mut VecDeque<K>) -> Result<(), E> {
        Ok(())
    }
}
