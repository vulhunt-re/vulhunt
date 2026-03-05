use fugue::ir::Address;

use crate::ir::Location;

pub mod guided;
pub mod xforce;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PredicatedLocation {
    pub location: Location,
    pub condition: bool,
}

impl PredicatedLocation {
    pub fn new(location: Location, condition: bool) -> Self {
        Self {
            location,
            condition,
        }
    }

    pub fn location(&self) -> Location {
        self.location
    }

    pub fn address(&self) -> Address {
        self.location.address
    }

    pub fn position(&self) -> usize {
        self.location.position
    }

    pub fn condition(&self) -> bool {
        self.condition
    }

    pub fn invert_condition(&self) -> Self {
        Self {
            condition: !self.condition,
            ..*self
        }
    }
}

pub trait Strategy {
    fn fully_explored(&mut self) -> bool;
    fn initialise_path(&mut self);
    fn terminate_path(&mut self);
    fn branch_path(&mut self, location: PredicatedLocation) -> bool;
}

#[derive(Default, Clone)]
pub struct DefaultStrategy;

impl Strategy for DefaultStrategy {
    fn fully_explored(&mut self) -> bool {
        true
    }

    fn initialise_path(&mut self) {}

    fn terminate_path(&mut self) {}

    fn branch_path(&mut self, location: PredicatedLocation) -> bool {
        location.condition()
    }
}
