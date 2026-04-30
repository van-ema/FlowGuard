use crate::graph::ProvenanceGraph;
use crate::graph::{EdgeId, NodeId};
use crate::labels::{Label, LabelState};
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

pub fn for_label(
    policy: PolicyId,
    sink: NodeId,
    label: Label,
    labels: &LabelState,
    graph: &ProvenanceGraph,
) -> Explanation {
    let path = labels
        .path_for(sink, label)
        .into_iter()
        .map(|edge_id| {
            let edge = graph
                .edge(edge_id)
                .unwrap_or_else(|| panic!("missing edge for explanation: {:?}", edge_id));
            ExplanationStep {
                from: edge.from,
                via_edge: edge.id,
                to: edge.to,
            }
        })
        .collect();

    Explanation { policy, sink, path }
}
