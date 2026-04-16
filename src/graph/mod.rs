use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::events::{Endpoint, PipeId, ProcessId, SocketId, Timestamp};

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
}
