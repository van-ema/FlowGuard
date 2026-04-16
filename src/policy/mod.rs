use crate::events::ObservedEvent;
use crate::graph::EdgeId;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PolicyId {
    ExternalToExec,
    SecretToNetwork,
    PromptToShellWithoutApproval,
    ExternalToExecutableWrite,
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
