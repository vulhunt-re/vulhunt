use std::collections::VecDeque;

use ahash::AHashSet;

use crate::eval::strategy::{PredicatedLocation, Strategy};

#[derive(Debug, Default, Clone)]
struct Linear {
    pending: AHashSet<PredicatedLocation>,
}

impl Linear {
    fn evaluate(&mut self, location: &PredicatedLocation) -> bool {
        self.pending.insert(*location)
    }
}

#[derive(Debug, Default, Clone)]
pub struct XForceStrategy {
    fitness: Linear,

    explored: Vec<PredicatedLocation>, // actual path of predicates taken
    switches: Vec<usize>,              // current path of switches to perform
    switches_id: Option<usize>,
    unexplored: VecDeque<Vec<usize>>, // global work-list of unexplored switched paths
}

impl XForceStrategy {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Strategy for XForceStrategy {
    fn fully_explored(&mut self) -> bool {
        self.unexplored.is_empty()
    }

    fn initialise_path(&mut self) {
        self.explored.clear();
        self.switches = self.unexplored.pop_front().unwrap_or_default();
        self.switches_id = if self.switches.is_empty() {
            None
        } else {
            Some(0)
        };
    }

    fn terminate_path(&mut self) {
        let (mut t, idx) = match self.switches_id {
            Some(v) if v > 0 => (self.switches.get(v - 1).copied().unwrap_or(0), v),
            _ => (0, 0),
        };

        if self.explored.len() > t {
            for pred in &self.explored[t..] {
                if self.fitness.evaluate(pred) {
                    let mut switches = if idx > 0 {
                        self.switches[..idx].to_vec()
                    } else {
                        Vec::new()
                    };
                    switches.push(t);
                    self.unexplored.push_back(switches);
                }
                t += 1;
            }
        }

        self.explored.clear()
    }

    fn branch_path(&mut self, location: PredicatedLocation) -> bool {
        let nlocation = if let Some(ref mut id) = &mut self.switches_id {
            if matches!(self.switches.get(*id), Some(nth) if *nth == self.explored.len()) {
                *id += 1;
                location.invert_condition()
            } else {
                location
            }
        } else {
            location
        };

        let output = nlocation.condition();
        self.explored.push(nlocation);
        output
    }
}
