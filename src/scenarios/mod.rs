use crate::enforce::EnforcementOutcome;
use crate::events::{Event, ObservedEvent};
use crate::explain::{self, Explanation};
use crate::graph::{EdgeKind, ProvenanceGraph};
use crate::labels::{Label, LabelState};
use crate::policy::{self, Violation};
use crate::state::{RuntimeObject, RuntimeState};

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

    pub fn run(&self, scenario: &Scenario) -> ScenarioOutcome {
        let mut replay = Replay::default();

        for observed in &scenario.events {
            replay.apply(observed);
        }

        replay.finish()
    }
}

#[derive(Default)]
struct Replay {
    runtime: RuntimeState,
    graph: ProvenanceGraph,
    labels: LabelState,
    explanations: Vec<Explanation>,
    violations: Vec<Violation>,
    blocked_event: Option<ObservedEvent>,
}

impl Replay {
    fn apply(&mut self, observed: &ObservedEvent) {
        match &observed.event {
            Event::AgentLaunch { process, .. } => {
                self.runtime.ensure_process(process);
                let process_node = self.graph.process_node(process);
                self.labels.seed(process_node, Label::Prompt);
            }
            Event::ApprovalGranted { process, .. } => {
                self.runtime.approve_process(process);
                let process_node = self.graph.process_node(process);
                self.labels.seed(process_node, Label::Approved);
            }
            Event::Fork { parent, child, .. } => {
                self.runtime
                    .fork_process(parent, child)
                    .unwrap_or_else(|err| panic!("{err}"));
                let parent_node = self.graph.process_node(parent);
                let child_node = self.graph.process_node(child);
                self.labels.copy_all(parent_node, child_node);
            }
            Event::Exec {
                parent, child, at, ..
            } => {
                self.runtime
                    .exec_process(parent, child)
                    .unwrap_or_else(|err| panic!("{err}"));
                let parent_node = self.graph.process_node(parent);
                let child_node = self.graph.process_node(child);
                let edge_id = self.graph.append_edge(
                    parent_node,
                    child_node,
                    EdgeKind::Exec,
                    *at,
                    observed.sequence,
                );
                self.labels.propagate_all(parent_node, child_node, edge_id);

                if let Some(violation) =
                    policy::check_external_to_exec(&self.labels, child_node, observed, edge_id)
                {
                    self.explanations.push(explain::for_label(
                        violation.policy,
                        child_node,
                        Label::External,
                        &self.labels,
                        &self.graph,
                    ));
                    self.violations.push(violation);
                    self.blocked_event = Some(observed.clone());
                }
            }
            Event::Open {
                process, fd, path, ..
            } => {
                self.runtime.map_open_file(process, *fd, path.clone());
            }
            Event::Pipe {
                process,
                pipe,
                read_fd,
                write_fd,
                ..
            } => {
                self.runtime.map_pipe(process, *pipe, *read_fd, *write_fd);
            }
            Event::Dup {
                process,
                from_fd,
                to_fd,
                ..
            } => {
                self.runtime
                    .dup_fd(process, *from_fd, *to_fd)
                    .unwrap_or_else(|err| panic!("{err}"));
            }
            Event::Close { process, fd, .. } => {
                self.runtime
                    .close_fd(process, *fd)
                    .unwrap_or_else(|err| panic!("{err}"));
            }
            Event::Read {
                process, fd, at, ..
            } => {
                let process_node = self.graph.process_node(process);
                let object = self
                    .runtime
                    .lookup_fd(process, *fd)
                    .unwrap_or_else(|err| panic!("{err}"))
                    .clone();
                let object_node = self.graph.runtime_object_node(&object);
                let edge_id = self.graph.append_edge(
                    object_node,
                    process_node,
                    EdgeKind::Read,
                    *at,
                    observed.sequence,
                );
                self.labels
                    .propagate_all(object_node, process_node, edge_id);
            }
            Event::Write {
                process, fd, at, ..
            } => {
                let process_node = self.graph.process_node(process);
                let object = self
                    .runtime
                    .lookup_fd(process, *fd)
                    .unwrap_or_else(|err| panic!("{err}"))
                    .clone();
                let object_node = self.graph.runtime_object_node(&object);
                let edge_id = self.graph.append_edge(
                    process_node,
                    object_node,
                    EdgeKind::Write,
                    *at,
                    observed.sequence,
                );
                self.labels
                    .propagate_all(process_node, object_node, edge_id);
            }
            Event::Connect {
                process,
                fd,
                endpoint,
                ..
            } => {
                self.runtime.connect_socket(process, *fd, endpoint.clone());
            }
            Event::Recv {
                process, fd, at, ..
            } => {
                let process_node = self.graph.process_node(process);
                let object = self
                    .runtime
                    .lookup_fd(process, *fd)
                    .unwrap_or_else(|err| panic!("{err}"));
                let socket_id = match object {
                    RuntimeObject::Socket { socket } => *socket,
                    other => panic!("recv on non-socket fd: {:?} {:?}", process, other),
                };
                let endpoint = self
                    .runtime
                    .socket_endpoint(socket_id)
                    .unwrap_or_else(|err| panic!("{err}"))
                    .clone();
                let endpoint_node = self.graph.endpoint_node(endpoint);
                self.labels.seed(endpoint_node, Label::External);
                let edge_id = self.graph.append_edge(
                    endpoint_node,
                    process_node,
                    EdgeKind::Recv,
                    *at,
                    observed.sequence,
                );
                self.labels
                    .propagate_label(endpoint_node, process_node, Label::External, edge_id);
            }
            Event::Send { .. } => {}
            Event::Exit { .. } => {}
        }
    }

    fn finish(self) -> ScenarioOutcome {
        let decision = policy::decide(self.violations);
        ScenarioOutcome {
            runtime: self.runtime,
            graph: self.graph,
            labels: self.labels,
            enforcement: EnforcementOutcome {
                decision,
                blocked_event: self.blocked_event,
            },
            explanations: self.explanations,
        }
    }
}
