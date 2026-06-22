use serde::Serialize;

use crate::events::{Event, EventRecord, ObservedEvent};
use crate::explain::Explanation;
use crate::graph::{Edge, EdgeKind, Node, NodeId, ProvenanceGraph};
use crate::labels::{Label, LabelState};
use crate::policy::{DecisionKind, PolicyId, Violation};
use crate::scenarios::{ReplayWarning, ReplayWarningKind, Scenario, ScenarioOutcome};

#[derive(Clone, Debug, Serialize)]
pub struct ReplayReport {
    pub schema_version: u32,
    pub scenario: String,
    pub decision: DecisionReport,
    pub event_records: Vec<EventRecordReport>,
    pub violations: Vec<ViolationReport>,
    pub warnings: Vec<WarningReport>,
    pub graph: GraphReport,
    pub node_labels: Vec<NodeLabelReport>,
    pub explanations: Vec<ExplanationReport>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DecisionReport {
    pub kind: String,
    pub violation_indices: Vec<usize>,
    pub blocked_event: Option<EventReport>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventRecordReport {
    pub sequence: u64,
    pub kind: String,
    pub event: String,
    pub source_node: Option<u64>,
    pub sink_node: Option<u64>,
    pub edge_id: Option<u64>,
    pub warning_indices: Vec<usize>,
    pub violation_indices: Vec<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ViolationReport {
    pub index: usize,
    pub policy: String,
    pub sink_event_sequence: u64,
    pub sink_event: EventReport,
    pub sink_edge: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WarningReport {
    pub index: usize,
    pub sequence: u64,
    pub kind: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct GraphReport {
    pub nodes: Vec<NodeReport>,
    pub edges: Vec<EdgeReport>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeReport {
    pub id: u64,
    pub kind: String,
    pub display: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct EdgeReport {
    pub id: u64,
    pub from: u64,
    pub to: u64,
    pub kind: String,
    pub timestamp: u64,
    pub event_sequence: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeLabelReport {
    pub node: u64,
    pub node_display: String,
    pub labels: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExplanationReport {
    pub index: usize,
    pub policy: String,
    pub sink_node: u64,
    pub sink_display: String,
    pub path: Vec<ExplanationStepReport>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExplanationStepReport {
    pub from: u64,
    pub from_display: String,
    pub via_edge: u64,
    pub edge_kind: String,
    pub to: u64,
    pub to_display: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventReport {
    pub sequence: u64,
    pub kind: String,
    pub summary: String,
}

impl ReplayReport {
    pub fn from_outcome(scenario: &Scenario, outcome: &ScenarioOutcome) -> Self {
        Self {
            schema_version: 1,
            scenario: scenario.name.clone(),
            decision: DecisionReport {
                kind: decision_kind_name(outcome.enforcement.decision.kind).to_string(),
                violation_indices: (0..outcome.enforcement.decision.violations.len()).collect(),
                blocked_event: outcome.enforcement.blocked_event.as_ref().map(event_report),
            },
            event_records: outcome.records.iter().map(event_record_report).collect(),
            violations: outcome
                .enforcement
                .decision
                .violations
                .iter()
                .enumerate()
                .map(|(index, violation)| violation_report(index, violation))
                .collect(),
            warnings: outcome
                .warnings
                .iter()
                .enumerate()
                .map(|(index, warning)| warning_report(index, warning))
                .collect(),
            graph: graph_report(&outcome.graph),
            node_labels: node_label_reports(&outcome.graph, &outcome.labels),
            explanations: outcome
                .explanations
                .iter()
                .enumerate()
                .map(|(index, explanation)| explanation_report(index, explanation, &outcome.graph))
                .collect(),
        }
    }
}

fn event_record_report(record: &EventRecord) -> EventRecordReport {
    EventRecordReport {
        sequence: record.observed.sequence,
        kind: event_kind(&record.observed.event).to_string(),
        event: format_observed_event(&record.observed),
        source_node: record.source_node.map(|node| node.0),
        sink_node: record.sink_node.map(|node| node.0),
        edge_id: record.edge_id.map(|edge| edge.0),
        warning_indices: record.warning_indices.clone(),
        violation_indices: record.violation_indices.clone(),
    }
}

fn violation_report(index: usize, violation: &Violation) -> ViolationReport {
    ViolationReport {
        index,
        policy: policy_name(violation.policy).to_string(),
        sink_event_sequence: violation.sink_event.sequence,
        sink_event: event_report(&violation.sink_event),
        sink_edge: violation.sink_edge.map(|edge| edge.0),
    }
}

fn warning_report(index: usize, warning: &ReplayWarning) -> WarningReport {
    WarningReport {
        index,
        sequence: warning.sequence,
        kind: warning_kind_name(warning.kind).to_string(),
        message: warning.message.clone(),
    }
}

fn graph_report(graph: &ProvenanceGraph) -> GraphReport {
    GraphReport {
        nodes: graph
            .nodes
            .iter()
            .map(|(id, node)| node_report(*id, node))
            .collect(),
        edges: graph.edges.iter().map(edge_report).collect(),
    }
}

fn node_report(id: NodeId, node: &Node) -> NodeReport {
    NodeReport {
        id: id.0,
        kind: node_kind(node).to_string(),
        display: format_node(node),
    }
}

fn edge_report(edge: &Edge) -> EdgeReport {
    EdgeReport {
        id: edge.id.0,
        from: edge.from.0,
        to: edge.to.0,
        kind: edge_kind_name(edge.kind).to_string(),
        timestamp: edge.at.0,
        event_sequence: edge.event_sequence,
    }
}

fn node_label_reports(graph: &ProvenanceGraph, labels: &LabelState) -> Vec<NodeLabelReport> {
    labels
        .by_node
        .iter()
        .map(|(node_id, _label_set)| NodeLabelReport {
            node: node_id.0,
            node_display: graph
                .nodes
                .get(node_id)
                .map(format_node)
                .unwrap_or_else(|| format!("node:{}", node_id.0)),
            labels: labels
                .active_labels_for(*node_id)
                .iter()
                .map(|label| label_name(*label).to_string())
                .collect(),
        })
        .collect()
}

fn explanation_report(
    index: usize,
    explanation: &Explanation,
    graph: &ProvenanceGraph,
) -> ExplanationReport {
    ExplanationReport {
        index,
        policy: policy_name(explanation.policy).to_string(),
        sink_node: explanation.sink.0,
        sink_display: graph
            .nodes
            .get(&explanation.sink)
            .map(format_node)
            .unwrap_or_else(|| format!("node:{}", explanation.sink.0)),
        path: explanation
            .path
            .iter()
            .map(|step| {
                let edge = graph.edge(step.via_edge);
                ExplanationStepReport {
                    from: step.from.0,
                    from_display: format_node_id(graph, step.from),
                    via_edge: step.via_edge.0,
                    edge_kind: edge
                        .map(|edge| edge_kind_name(edge.kind).to_string())
                        .unwrap_or_else(|| "Missing".to_string()),
                    to: step.to.0,
                    to_display: format_node_id(graph, step.to),
                }
            })
            .collect(),
    }
}

fn event_report(observed: &ObservedEvent) -> EventReport {
    EventReport {
        sequence: observed.sequence,
        kind: event_kind(&observed.event).to_string(),
        summary: format_observed_event(observed),
    }
}

pub fn format_observed_event(observed: &ObservedEvent) -> String {
    match &observed.event {
        Event::AgentLaunch {
            process, command, ..
        } => format!(
            "AGENT_LAUNCH proc:{}@{} command:{}",
            process.pid,
            process.start_time.0,
            command.join(" ")
        ),
        Event::ApprovalGranted {
            process, reason, ..
        } => format!(
            "APPROVAL_GRANTED proc:{}@{} reason:{}",
            process.pid, process.start_time.0, reason
        ),
        Event::DeclassificationGranted {
            process, reason, ..
        } => format!(
            "DECLASSIFICATION_GRANTED proc:{}@{} reason:{}",
            process.pid, process.start_time.0, reason
        ),
        Event::Fork { parent, child, .. } => format!(
            "FORK proc:{}@{} -> proc:{}@{}",
            parent.pid, parent.start_time.0, child.pid, child.start_time.0
        ),
        Event::Exec {
            parent, program, ..
        } => format!(
            "EXEC proc:{}@{} program:{}",
            parent.pid,
            parent.start_time.0,
            program.display()
        ),
        Event::Open {
            process, fd, path, ..
        } => format!(
            "OPEN proc:{}@{} fd:{} path:{}",
            process.pid,
            process.start_time.0,
            fd.0,
            path.display()
        ),
        Event::FdSnapshot {
            process, entries, ..
        } => format!(
            "FD_SNAPSHOT proc:{}@{} entries:{}",
            process.pid,
            process.start_time.0,
            entries.len()
        ),
        Event::Pipe {
            process,
            pipe,
            read_fd,
            write_fd,
            ..
        } => format!(
            "PIPE proc:{}@{} pipe:{} read_fd:{} write_fd:{}",
            process.pid, process.start_time.0, pipe.0, read_fd.0, write_fd.0
        ),
        Event::Dup {
            process,
            from_fd,
            to_fd,
            ..
        } => format!(
            "DUP proc:{}@{} from_fd:{} to_fd:{}",
            process.pid, process.start_time.0, from_fd.0, to_fd.0
        ),
        Event::Close { process, fd, .. } => {
            format!(
                "CLOSE proc:{}@{} fd:{}",
                process.pid, process.start_time.0, fd.0
            )
        }
        Event::Read {
            process, fd, len, ..
        } => format!(
            "READ proc:{}@{} fd:{} len:{}",
            process.pid, process.start_time.0, fd.0, len
        ),
        Event::Write {
            process, fd, len, ..
        } => format!(
            "WRITE proc:{}@{} fd:{} len:{}",
            process.pid, process.start_time.0, fd.0, len
        ),
        Event::Connect {
            process,
            fd,
            endpoint,
            ..
        } => format!(
            "CONNECT proc:{}@{} fd:{} endpoint:{}:{}",
            process.pid, process.start_time.0, fd.0, endpoint.host, endpoint.port
        ),
        Event::Recv {
            process, fd, len, ..
        } => format!(
            "RECV proc:{}@{} fd:{} len:{}",
            process.pid, process.start_time.0, fd.0, len
        ),
        Event::Send {
            process, fd, len, ..
        } => format!(
            "SEND proc:{}@{} fd:{} len:{}",
            process.pid, process.start_time.0, fd.0, len
        ),
        Event::SocketCreate {
            process,
            fd,
            family,
            socket_type,
            protocol,
            ..
        } => format!(
            "SOCKET_CREATE proc:{}@{} fd:{} family:{family:?} type:{socket_type:?} protocol:{protocol:?}",
            process.pid, process.start_time.0, fd.0
        ),
        Event::SetSockOpt {
            process,
            fd,
            level,
            option,
            ..
        } => format!(
            "SET_SOCK_OPT proc:{}@{} fd:{} level:{level:?} option:{option:?}",
            process.pid, process.start_time.0, fd.0
        ),
        Event::Splice {
            process,
            from_fd,
            to_fd,
            len,
            ..
        } => format!(
            "SPLICE proc:{}@{} from_fd:{} to_fd:{} len:{}",
            process.pid, process.start_time.0, from_fd.0, to_fd.0, len
        ),
        Event::Exit { process, .. } => {
            format!("EXIT proc:{}@{}", process.pid, process.start_time.0)
        }
    }
}

pub fn format_node_id(graph: &ProvenanceGraph, node_id: NodeId) -> String {
    graph
        .nodes
        .get(&node_id)
        .map(format_node)
        .unwrap_or_else(|| format!("node:{}", node_id.0))
}

pub fn format_node(node: &Node) -> String {
    match node {
        Node::Process(process) => format!("proc:{}@{}", process.pid, process.start_time.0),
        Node::File { path } => format!("file:{}", path.display()),
        Node::Pipe { pipe } => format!("pipe:{}", pipe.0),
        Node::Socket { socket } => format!("socket:{}", socket.0),
        Node::Endpoint(endpoint) => format!("endpoint:{}:{}", endpoint.host, endpoint.port),
        Node::UnknownFd { description } => format!("unknown-fd:{description}"),
    }
}

pub fn policy_name(policy: PolicyId) -> &'static str {
    match policy {
        PolicyId::ExternalToExec => "ExternalToExec",
        PolicyId::SecretToNetwork => "SecretToNetwork",
        PolicyId::PromptToShellWithoutApproval => "PromptToShellWithoutApproval",
        PolicyId::ExternalToExecutableWrite => "ExternalToExecutableWrite",
        PolicyId::PromptToContainerRuntimeSocket => "PromptToContainerRuntimeSocket",
        PolicyId::CopyFailAfAlgPattern => "CopyFailAfAlgPattern",
    }
}

pub fn decision_kind_name(kind: DecisionKind) -> &'static str {
    match kind {
        DecisionKind::Allow => "Allow",
        DecisionKind::Alert => "Alert",
        DecisionKind::RequireApproval => "RequireApproval",
        DecisionKind::Block => "Block",
    }
}

pub fn edge_kind_name(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Read => "Read",
        EdgeKind::Write => "Write",
        EdgeKind::Recv => "Recv",
        EdgeKind::Send => "Send",
        EdgeKind::Fork => "Fork",
        EdgeKind::Exec => "Exec",
        EdgeKind::Connect => "Connect",
    }
}

fn event_kind(event: &Event) -> &'static str {
    match event {
        Event::AgentLaunch { .. } => "AgentLaunch",
        Event::ApprovalGranted { .. } => "ApprovalGranted",
        Event::DeclassificationGranted { .. } => "DeclassificationGranted",
        Event::Fork { .. } => "Fork",
        Event::Exec { .. } => "Exec",
        Event::Open { .. } => "Open",
        Event::FdSnapshot { .. } => "FdSnapshot",
        Event::Pipe { .. } => "Pipe",
        Event::Dup { .. } => "Dup",
        Event::Close { .. } => "Close",
        Event::Read { .. } => "Read",
        Event::Write { .. } => "Write",
        Event::Connect { .. } => "Connect",
        Event::Recv { .. } => "Recv",
        Event::Send { .. } => "Send",
        Event::SocketCreate { .. } => "SocketCreate",
        Event::SetSockOpt { .. } => "SetSockOpt",
        Event::Splice { .. } => "Splice",
        Event::Exit { .. } => "Exit",
    }
}

fn node_kind(node: &Node) -> &'static str {
    match node {
        Node::Process(_) => "Process",
        Node::File { .. } => "File",
        Node::Pipe { .. } => "Pipe",
        Node::Socket { .. } => "Socket",
        Node::Endpoint(_) => "Endpoint",
        Node::UnknownFd { .. } => "UnknownFd",
    }
}

fn warning_kind_name(kind: ReplayWarningKind) -> &'static str {
    match kind {
        ReplayWarningKind::UnknownProcess => "UnknownProcess",
        ReplayWarningKind::MissingFd => "MissingFd",
        ReplayWarningKind::NonSocketFd => "NonSocketFd",
        ReplayWarningKind::MissingSocketEndpoint => "MissingSocketEndpoint",
        ReplayWarningKind::InconsistentState => "InconsistentState",
    }
}

fn label_name(label: Label) -> &'static str {
    match label {
        Label::Prompt => "Prompt",
        Label::External => "External",
        Label::Secret => "Secret",
        Label::TrustedLocal => "TrustedLocal",
        Label::Approved => "Approved",
    }
}
