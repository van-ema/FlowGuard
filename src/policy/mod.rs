use crate::events::{AddressFamily, Event, ObservedEvent};
use crate::graph::{EdgeId, NodeId};
use crate::labels::{Label, LabelState};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PolicyId {
    ExternalToExec,
    SecretToNetwork,
    PromptToShellWithoutApproval,
    ExternalToExecutableWrite,
    CopyFailAfAlgPattern,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DecisionKind {
    Allow,
    Alert,
    RequireApproval,
    Block,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Violation {
    pub policy: PolicyId,
    pub sink_event: ObservedEvent,
    pub sink_edge: Option<EdgeId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decision {
    pub kind: DecisionKind,
    pub violations: Vec<Violation>,
}

pub fn check_external_to_exec(
    labels: &LabelState,
    process_node: NodeId,
    sink_event: &ObservedEvent,
    sink_edge: EdgeId,
) -> Option<Violation> {
    if labels.has_label(process_node, Label::External) {
        return Some(Violation {
            policy: PolicyId::ExternalToExec,
            sink_event: sink_event.clone(),
            sink_edge: Some(sink_edge),
        });
    }

    None
}

pub fn check_secret_to_network(
    labels: &LabelState,
    endpoint_node: NodeId,
    sink_event: &ObservedEvent,
    sink_edge: EdgeId,
) -> Option<Violation> {
    if labels.has_label(endpoint_node, Label::Secret) {
        return Some(Violation {
            policy: PolicyId::SecretToNetwork,
            sink_event: sink_event.clone(),
            sink_edge: Some(sink_edge),
        });
    }

    None
}

pub fn check_copy_fail_af_alg_pattern(
    labels: &LabelState,
    process_node: NodeId,
    sink_event: &ObservedEvent,
) -> Option<Violation> {
    let Event::SocketCreate {
        family: AddressFamily::AfAlg,
        ..
    } = &sink_event.event
    else {
        return None;
    };

    if labels.has_label(process_node, Label::Prompt) {
        return Some(Violation {
            policy: PolicyId::CopyFailAfAlgPattern,
            sink_event: sink_event.clone(),
            sink_edge: None,
        });
    }

    None
}

pub fn decide(violations: Vec<Violation>) -> Decision {
    let kind = if violations.is_empty() {
        DecisionKind::Allow
    } else {
        DecisionKind::Block
    };

    Decision { kind, violations }
}
