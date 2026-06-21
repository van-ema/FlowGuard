use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use crate::events::{Endpoint, PipeId, ProcessId, SocketId, Timestamp};
use crate::state::RuntimeObject;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EdgeId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EdgeKind {
    Read,
    Write,
    Recv,
    Send,
    Fork,
    Exec,
    Connect,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Node {
    Process(ProcessId),
    File { path: PathBuf },
    Pipe { pipe: PipeId },
    Socket { socket: SocketId },
    Endpoint(Endpoint),
    UnknownFd { description: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edge {
    pub id: EdgeId,
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
    pub at: Timestamp,
    pub event_sequence: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProvenanceGraph {
    pub nodes: BTreeMap<NodeId, Node>,
    pub edges: Vec<Edge>,
    node_ids: HashMap<Node, NodeId>,
    next_node_id: u64,
    next_edge_id: u64,
}

impl ProvenanceGraph {
    pub fn process_node(&mut self, process: &ProcessId) -> NodeId {
        self.ensure_node(Node::Process(process.clone()))
    }

    pub fn endpoint_node(&mut self, endpoint: Endpoint) -> NodeId {
        self.ensure_node(Node::Endpoint(endpoint))
    }

    pub fn runtime_object_node(&mut self, object: &RuntimeObject) -> NodeId {
        match object {
            RuntimeObject::File { path } => self.ensure_node(Node::File { path: path.clone() }),
            RuntimeObject::PipeReadEnd { pipe } | RuntimeObject::PipeWriteEnd { pipe } => {
                self.ensure_node(Node::Pipe { pipe: *pipe })
            }
            RuntimeObject::Socket { socket } => self.ensure_node(Node::Socket { socket: *socket }),
            RuntimeObject::UnknownFd { description } => self.ensure_node(Node::UnknownFd {
                description: description.clone(),
            }),
        }
    }

    pub fn append_edge(
        &mut self,
        from: NodeId,
        to: NodeId,
        kind: EdgeKind,
        at: Timestamp,
        event_sequence: u64,
    ) -> EdgeId {
        self.next_edge_id += 1;
        let edge_id = EdgeId(self.next_edge_id);
        self.edges.push(Edge {
            id: edge_id,
            from,
            to,
            kind,
            at,
            event_sequence,
        });
        edge_id
    }

    pub fn edge(&self, edge_id: EdgeId) -> Option<&Edge> {
        self.edges.iter().find(|edge| edge.id == edge_id)
    }

    fn ensure_node(&mut self, node: Node) -> NodeId {
        if let Some(node_id) = self.node_ids.get(&node) {
            return *node_id;
        }

        self.next_node_id += 1;
        let node_id = NodeId(self.next_node_id);
        self.nodes.insert(node_id, node.clone());
        self.node_ids.insert(node, node_id);
        node_id
    }
}
