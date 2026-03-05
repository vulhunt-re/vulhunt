use std::collections::VecDeque;

use fugue::ir::Address;

use super::{PredicatedLocation, Strategy};

#[derive(Debug, Default, Clone)]
pub struct GuidedStrategy {
    path: VecDeque<Address>,
}

impl GuidedStrategy {
    pub fn new<I>(path: I) -> Self
    where
        I: Iterator<Item = Address>,
    {
        Self {
            path: path.collect(),
        }
    }
}

impl Strategy for GuidedStrategy {
    fn fully_explored(&mut self) -> bool {
        self.path.is_empty()
    }

    fn initialise_path(&mut self) {}

    fn terminate_path(&mut self) {}

    fn branch_path(&mut self, location: PredicatedLocation) -> bool {
        if location.position() == 0 {
            if let Some(front) = self.path.pop_front() {
                if location.address() == front {
                    location.condition
                } else {
                    !location.condition
                }
            } else {
                location.condition
            }
        } else {
            location.condition
        }
    }
}
