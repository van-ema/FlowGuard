use crate::graph::{EdgeId, NodeId};
use crate::policy::PolicyId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplanationStep {
    pub from: NodeId,
    pub via_edge: EdgeId,
    pub to: NodeId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Explanation {
    pub policy: PolicyId,
    pub sink: NodeId,
    pub path: Vec<ExplanationStep>,
}
