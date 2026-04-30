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
    paths: BTreeMap<(NodeId, Label), Vec<EdgeId>>,
}

impl LabelState {
    pub fn seed(&mut self, node: NodeId, label: Label) {
        let inserted = self.by_node.entry(node).or_default().labels.insert(label);

        if inserted {
            self.paths.insert((node, label), Vec::new());
        }
    }

    pub fn has_label(&self, node: NodeId, label: Label) -> bool {
        self.by_node
            .get(&node)
            .is_some_and(|set| set.labels.contains(&label))
    }

    pub fn copy_all(&mut self, from: NodeId, to: NodeId) {
        for label in self.labels_for(from) {
            let inserted = self.by_node.entry(to).or_default().labels.insert(label);
            if inserted {
                let path = self.paths.get(&(from, label)).cloned().unwrap_or_default();
                self.paths.insert((to, label), path);
            }
        }
    }

    pub fn propagate_all(&mut self, from: NodeId, to: NodeId, edge_id: EdgeId) {
        for label in self.labels_for(from) {
            self.propagate_label(from, to, label, edge_id);
        }
    }

    pub fn propagate_label(&mut self, from: NodeId, to: NodeId, label: Label, edge_id: EdgeId) {
        let inserted = self.by_node.entry(to).or_default().labels.insert(label);

        if inserted {
            let mut path = self.paths.get(&(from, label)).cloned().unwrap_or_default();
            path.push(edge_id);
            self.paths.insert((to, label), path);
        }
    }

    pub fn path_for(&self, node: NodeId, label: Label) -> Vec<EdgeId> {
        self.paths.get(&(node, label)).cloned().unwrap_or_default()
    }

    fn labels_for(&self, node: NodeId) -> Vec<Label> {
        self.by_node
            .get(&node)
            .map(|set| set.labels.iter().copied().collect())
            .unwrap_or_default()
    }
}
