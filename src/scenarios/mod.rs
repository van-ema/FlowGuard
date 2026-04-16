use crate::enforce::EnforcementOutcome;
use crate::events::{Event, ObservedEvent};
use crate::explain::Explanation;
use crate::graph::ProvenanceGraph;
use crate::labels::LabelState;
use crate::policy::{Decision, DecisionKind};
use crate::state::RuntimeState;

pub mod curl_bash;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scenario {
    pub name: &'static str,
    pub events: Vec<ObservedEvent>,
}

impl Scenario {
    pub fn new(name: &'static str, events: Vec<Event>) -> Self {
        let events = events
            .into_iter()
            .enumerate()
            .map(|(sequence, event)| ObservedEvent {
                sequence: sequence as u64,
                event,
            })
            .collect();

        Self { name, events }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioOutcome {
    pub runtime: RuntimeState,
    pub graph: ProvenanceGraph,
    pub labels: LabelState,
    pub enforcement: EnforcementOutcome,
    pub explanations: Vec<Explanation>,
}

pub struct ScenarioRunner;

impl ScenarioRunner {
    pub fn new() -> Self {
        Self
    }

    pub fn run(&self, _scenario: &Scenario) -> ScenarioOutcome {
        ScenarioOutcome {
            runtime: RuntimeState::default(),
            graph: ProvenanceGraph::default(),
            labels: LabelState::default(),
            enforcement: EnforcementOutcome {
                decision: Decision {
                    kind: DecisionKind::Allow,
                    violations: Vec::new(),
                },
                blocked_event: None,
            },
            explanations: Vec::new(),
        }
    }
}
