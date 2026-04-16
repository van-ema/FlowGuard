use std::collections::{BTreeMap, BTreeSet};

use crate::graph::{EdgeId, NodeId};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Label {
    Prompt,
    External,
    Secret,
    TrustedLocal,
    Approved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Witness {
    pub source: NodeId,
    pub via_edge: Option<EdgeId>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LabelSet {
    pub labels: BTreeSet<Label>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LabelState {
    pub by_node: BTreeMap<NodeId, LabelSet>,
}
