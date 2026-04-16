use std::path::PathBuf;

use crate::graph::{EdgeId, NodeId};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StartTime(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Fd(pub i32);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PipeId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SocketId(pub u64);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcessId {
    pub pid: u32,
    pub start_time: StartTime,
}

impl ProcessId {
    pub const fn new(pid: u32, start_time: StartTime) -> Self {
        Self { pid, start_time }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    AgentLaunch {
        process: ProcessId,
        command: Vec<String>,
        at: Timestamp,
    },
    ApprovalGranted {
        process: ProcessId,
        reason: String,
        at: Timestamp,
    },
    Fork {
        parent: ProcessId,
        child: ProcessId,
        at: Timestamp,
    },
    Exec {
        parent: ProcessId,
        child: ProcessId,
        program: PathBuf,
        argv: Vec<String>,
        at: Timestamp,
    },
    Open {
        process: ProcessId,
        fd: Fd,
        path: PathBuf,
        at: Timestamp,
    },
    Pipe {
        process: ProcessId,
        pipe: PipeId,
        read_fd: Fd,
        write_fd: Fd,
        at: Timestamp,
    },
    Dup {
        process: ProcessId,
        from_fd: Fd,
        to_fd: Fd,
        at: Timestamp,
    },
    Close {
        process: ProcessId,
        fd: Fd,
        at: Timestamp,
    },
    Read {
        process: ProcessId,
        fd: Fd,
        len: usize,
        at: Timestamp,
    },
    Write {
        process: ProcessId,
        fd: Fd,
        len: usize,
        at: Timestamp,
    },
    Connect {
        process: ProcessId,
        fd: Fd,
        endpoint: Endpoint,
        at: Timestamp,
    },
    Recv {
        process: ProcessId,
        fd: Fd,
        len: usize,
        at: Timestamp,
    },
    Send {
        process: ProcessId,
        fd: Fd,
        len: usize,
        at: Timestamp,
    },
    Exit {
        process: ProcessId,
        at: Timestamp,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedEvent {
    pub sequence: u64,
    pub event: Event,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRecord {
    pub observed: ObservedEvent,
    pub source_node: Option<NodeId>,
    pub sink_node: Option<NodeId>,
    pub edge_id: Option<EdgeId>,
}
