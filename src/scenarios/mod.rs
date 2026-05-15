use crate::enforce::EnforcementOutcome;
use crate::events::{Event, EventRecord, Fd, ObservedEvent, ProcessId, SocketId};
use crate::explain::{self, Explanation};
use crate::graph::{EdgeKind, ProvenanceGraph};
use crate::labels::{Label, LabelState};
use crate::policy::{self, Violation};
use crate::state::{RuntimeObject, RuntimeState};

pub mod curl_bash;
pub mod demo;
pub mod file;
pub mod secret_to_network;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scenario {
    pub name: String,
    pub events: Vec<ObservedEvent>,
}

impl Scenario {
    pub fn new(name: impl Into<String>, events: Vec<Event>) -> Self {
        let events = events
            .into_iter()
            .enumerate()
            .map(|(sequence, event)| ObservedEvent {
                sequence: sequence as u64,
                event,
            })
            .collect();

        Self {
            name: name.into(),
            events,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioOutcome {
    pub runtime: RuntimeState,
    pub graph: ProvenanceGraph,
    pub labels: LabelState,
    pub records: Vec<EventRecord>,
    pub enforcement: EnforcementOutcome,
    pub explanations: Vec<Explanation>,
    pub warnings: Vec<ReplayWarning>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayWarning {
    pub sequence: u64,
    pub kind: ReplayWarningKind,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayWarningKind {
    UnknownProcess,
    MissingFd,
    NonSocketFd,
    MissingSocketEndpoint,
    InconsistentState,
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
    records: Vec<EventRecord>,
    explanations: Vec<Explanation>,
    violations: Vec<Violation>,
    warnings: Vec<ReplayWarning>,
    blocked_event: Option<ObservedEvent>,
}

#[derive(Default)]
struct EventEffect {
    source_node: Option<crate::graph::NodeId>,
    sink_node: Option<crate::graph::NodeId>,
    edge_id: Option<crate::graph::EdgeId>,
}

impl Replay {
    fn apply(&mut self, observed: &ObservedEvent) {
        let warning_start = self.warnings.len();
        let violation_start = self.violations.len();
        let effect = self.apply_event(observed);

        self.records.push(EventRecord {
            observed: observed.clone(),
            source_node: effect.source_node,
            sink_node: effect.sink_node,
            edge_id: effect.edge_id,
            warning_indices: (warning_start..self.warnings.len()).collect(),
            violation_indices: (violation_start..self.violations.len()).collect(),
        });
    }

    fn apply_event(&mut self, observed: &ObservedEvent) -> EventEffect {
        let mut effect = EventEffect::default();

        match &observed.event {
            Event::AgentLaunch { process, .. } => {
                self.runtime.ensure_process(process);
                let process_node = self.graph.process_node(process);
                self.labels.seed(process_node, Label::Prompt);
                effect.sink_node = Some(process_node);
            }
            Event::ApprovalGranted { process, .. } => {
                self.runtime.approve_process(process);
                let process_node = self.graph.process_node(process);
                self.labels.seed(process_node, Label::Approved);
                effect.sink_node = Some(process_node);
            }
            Event::Fork { parent, child, at } => {
                if let Err(err) = self.runtime.fork_process(parent, child) {
                    self.warn_state_error(observed, err);
                    return effect;
                }
                let parent_node = self.graph.process_node(parent);
                let child_node = self.graph.process_node(child);
                let edge_id = self.graph.append_edge(
                    parent_node,
                    child_node,
                    EdgeKind::Fork,
                    *at,
                    observed.sequence,
                );
                self.labels.propagate_all(parent_node, child_node, edge_id);
                effect.source_node = Some(parent_node);
                effect.sink_node = Some(child_node);
                effect.edge_id = Some(edge_id);
            }
            Event::Exec {
                parent, child, at, ..
            } => {
                if let Err(err) = self.runtime.exec_process(parent, child) {
                    self.warn_state_error(observed, err);
                    return effect;
                }
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
                effect.source_node = Some(parent_node);
                effect.sink_node = Some(child_node);
                effect.edge_id = Some(edge_id);

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

                if let Some(violation) = policy::check_prompt_to_shell_without_approval(
                    &self.labels,
                    child_node,
                    observed,
                    edge_id,
                ) {
                    self.explanations.push(explain::for_label(
                        violation.policy,
                        child_node,
                        Label::Prompt,
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
                let process_node = self.graph.process_node(process);
                let file_node = self
                    .graph
                    .runtime_object_node(&RuntimeObject::File { path: path.clone() });
                effect.source_node = Some(process_node);
                effect.sink_node = Some(file_node);
                if is_secret_path(path) {
                    self.labels.seed(file_node, Label::Secret);
                }

                if let Some(violation) = policy::check_prompt_to_container_runtime_socket(
                    &self.labels,
                    process_node,
                    path,
                    observed,
                ) {
                    self.explanations.push(explain::for_label(
                        violation.policy,
                        process_node,
                        Label::Prompt,
                        &self.labels,
                        &self.graph,
                    ));
                    self.violations.push(violation);
                    self.blocked_event = Some(observed.clone());
                }
            }
            Event::Pipe {
                process,
                pipe,
                read_fd,
                write_fd,
                ..
            } => {
                self.runtime.map_pipe(process, *pipe, *read_fd, *write_fd);
                let pipe_node = self
                    .graph
                    .runtime_object_node(&RuntimeObject::PipeReadEnd { pipe: *pipe });
                effect.sink_node = Some(pipe_node);
            }
            Event::Dup {
                process,
                from_fd,
                to_fd,
                ..
            } => {
                if let Err(err) = self.runtime.dup_fd(process, *from_fd, *to_fd) {
                    self.warn_state_error(observed, err);
                } else if let Some(object) = self.lookup_fd(observed, process, *to_fd) {
                    let process_node = self.graph.process_node(process);
                    let object_node = self.graph.runtime_object_node(&object);
                    effect.source_node = Some(process_node);
                    effect.sink_node = Some(object_node);
                }
            }
            Event::Close { process, fd, .. } => {
                if let Err(err) = self.runtime.close_fd(process, *fd) {
                    self.warn_state_error(observed, err);
                } else {
                    let process_node = self.graph.process_node(process);
                    effect.source_node = Some(process_node);
                }
            }
            Event::Read {
                process, fd, at, ..
            } => {
                let Some(object) = self.lookup_fd(observed, process, *fd) else {
                    return effect;
                };
                let process_node = self.graph.process_node(process);
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
                effect.source_node = Some(object_node);
                effect.sink_node = Some(process_node);
                effect.edge_id = Some(edge_id);
            }
            Event::Write {
                process, fd, at, ..
            } => {
                let Some(object) = self.lookup_fd(observed, process, *fd) else {
                    return effect;
                };
                let process_node = self.graph.process_node(process);
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
                effect.source_node = Some(process_node);
                effect.sink_node = Some(object_node);
                effect.edge_id = Some(edge_id);

                if let RuntimeObject::File { path } = &object {
                    if let Some(violation) = policy::check_external_to_executable_write(
                        &self.labels,
                        object_node,
                        path,
                        observed,
                        edge_id,
                    ) {
                        self.explanations.push(explain::for_label(
                            violation.policy,
                            object_node,
                            Label::External,
                            &self.labels,
                            &self.graph,
                        ));
                        self.violations.push(violation);
                        self.blocked_event = Some(observed.clone());
                    }
                }
            }
            Event::Connect {
                process,
                fd,
                endpoint,
                at,
            } => {
                self.runtime.connect_socket(process, *fd, endpoint.clone());
                let process_node = self.graph.process_node(process);
                let endpoint_node = self.graph.endpoint_node(endpoint.clone());
                let edge_id = self.graph.append_edge(
                    process_node,
                    endpoint_node,
                    EdgeKind::Connect,
                    *at,
                    observed.sequence,
                );
                effect.source_node = Some(process_node);
                effect.sink_node = Some(endpoint_node);
                effect.edge_id = Some(edge_id);
            }
            Event::Recv {
                process, fd, at, ..
            } => {
                let Some(object) = self.lookup_fd(observed, process, *fd) else {
                    return effect;
                };
                let Some(socket_id) = self.socket_id_for_fd(observed, process, *fd, &object) else {
                    return effect;
                };
                let Some(endpoint) = self.socket_endpoint(observed, socket_id) else {
                    return effect;
                };
                let process_node = self.graph.process_node(process);
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
                effect.source_node = Some(endpoint_node);
                effect.sink_node = Some(process_node);
                effect.edge_id = Some(edge_id);
            }
            Event::Send {
                process, fd, at, ..
            } => {
                let Some(object) = self.lookup_fd(observed, process, *fd) else {
                    return effect;
                };
                let Some(socket_id) = self.socket_id_for_fd(observed, process, *fd, &object) else {
                    return effect;
                };
                let Some(endpoint) = self.socket_endpoint(observed, socket_id) else {
                    return effect;
                };
                let process_node = self.graph.process_node(process);
                let endpoint_node = self.graph.endpoint_node(endpoint);
                let edge_id = self.graph.append_edge(
                    process_node,
                    endpoint_node,
                    EdgeKind::Send,
                    *at,
                    observed.sequence,
                );
                self.labels
                    .propagate_all(process_node, endpoint_node, edge_id);
                effect.source_node = Some(process_node);
                effect.sink_node = Some(endpoint_node);
                effect.edge_id = Some(edge_id);

                if let Some(violation) =
                    policy::check_secret_to_network(&self.labels, endpoint_node, observed, edge_id)
                {
                    self.explanations.push(explain::for_label(
                        violation.policy,
                        endpoint_node,
                        Label::Secret,
                        &self.labels,
                        &self.graph,
                    ));
                    self.violations.push(violation);
                    self.blocked_event = Some(observed.clone());
                }
            }
            Event::SocketCreate { process, .. } => {
                let process_node = self.graph.process_node(process);
                effect.source_node = Some(process_node);

                if let Some(violation) =
                    policy::check_copy_fail_af_alg_pattern(&self.labels, process_node, observed)
                {
                    self.violations.push(violation);
                    self.blocked_event = Some(observed.clone());
                }
            }
            Event::SetSockOpt { .. } => {}
            Event::Splice { .. } => {}
            Event::Exit { .. } => {}
        }

        effect
    }

    fn lookup_fd(
        &mut self,
        observed: &ObservedEvent,
        process: &ProcessId,
        fd: Fd,
    ) -> Option<RuntimeObject> {
        match self.runtime.lookup_fd(process, fd) {
            Ok(object) => Some(object.clone()),
            Err(err) => {
                self.warn_state_error(observed, err);
                None
            }
        }
    }

    fn socket_id_for_fd(
        &mut self,
        observed: &ObservedEvent,
        process: &ProcessId,
        fd: Fd,
        object: &RuntimeObject,
    ) -> Option<SocketId> {
        match object {
            RuntimeObject::Socket { socket } => Some(*socket),
            other => {
                self.warn(
                    observed,
                    ReplayWarningKind::NonSocketFd,
                    format!("socket operation on non-socket fd: {process:?} {fd:?} {other:?}"),
                );
                None
            }
        }
    }

    fn socket_endpoint(
        &mut self,
        observed: &ObservedEvent,
        socket: SocketId,
    ) -> Option<crate::events::Endpoint> {
        match self.runtime.socket_endpoint(socket) {
            Ok(endpoint) => Some(endpoint.clone()),
            Err(err) => {
                self.warn_state_error(observed, err);
                None
            }
        }
    }

    fn warn_state_error(&mut self, observed: &ObservedEvent, message: String) {
        self.warn(observed, classify_state_error(&message), message);
    }

    fn warn(&mut self, observed: &ObservedEvent, kind: ReplayWarningKind, message: String) {
        self.warnings.push(ReplayWarning {
            sequence: observed.sequence,
            kind,
            message,
        });
    }

    fn finish(self) -> ScenarioOutcome {
        let decision = policy::decide(self.violations);
        ScenarioOutcome {
            runtime: self.runtime,
            graph: self.graph,
            labels: self.labels,
            records: self.records,
            enforcement: EnforcementOutcome {
                decision,
                blocked_event: self.blocked_event,
            },
            explanations: self.explanations,
            warnings: self.warnings,
        }
    }
}

fn classify_state_error(message: &str) -> ReplayWarningKind {
    if message.starts_with("unknown") {
        ReplayWarningKind::UnknownProcess
    } else if message.contains("missing") && message.contains("fd") {
        ReplayWarningKind::MissingFd
    } else if message.contains("missing endpoint") {
        ReplayWarningKind::MissingSocketEndpoint
    } else {
        ReplayWarningKind::InconsistentState
    }
}

fn is_secret_path(path: &std::path::Path) -> bool {
    path.starts_with("/home/user/.ssh")
}

#[cfg(test)]
mod tests {
    use crate::events::{Endpoint, Event, Fd, ProcessId, StartTime, Timestamp};
    use crate::graph::{EdgeKind, Node};
    use crate::policy::DecisionKind;

    use super::{Scenario, ScenarioRunner};

    #[test]
    fn connect_records_process_to_endpoint_edge_without_label_propagation() {
        let process = ProcessId::new(42, StartTime(100));
        let endpoint = Endpoint::tcp("example.test", 443);
        let scenario = Scenario::new(
            "connect_edge",
            vec![
                Event::AgentLaunch {
                    process: process.clone(),
                    command: vec!["curl".into(), "https://example.test".into()],
                    at: Timestamp(1),
                },
                Event::Connect {
                    process: process.clone(),
                    fd: Fd(3),
                    endpoint: endpoint.clone(),
                    at: Timestamp(2),
                },
            ],
        );

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Allow);
        assert_eq!(outcome.graph.edges.len(), 1);

        let edge = &outcome.graph.edges[0];
        assert_eq!(edge.kind, EdgeKind::Connect);
        assert_eq!(edge.at, Timestamp(2));
        assert_eq!(edge.event_sequence, 1);
        assert_eq!(
            outcome.graph.nodes.get(&edge.from),
            Some(&Node::Process(process))
        );
        assert_eq!(
            outcome.graph.nodes.get(&edge.to),
            Some(&Node::Endpoint(endpoint))
        );
    }
}
