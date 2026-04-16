use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::events::{Fd, PipeId, ProcessId, SocketId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeObject {
    File { path: PathBuf },
    PipeReadEnd { pipe: PipeId },
    PipeWriteEnd { pipe: PipeId },
    Socket { socket: SocketId },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FdTable {
    entries: BTreeMap<Fd, RuntimeObject>,
}

impl FdTable {
    pub fn insert(&mut self, fd: Fd, object: RuntimeObject) {
        self.entries.insert(fd, object);
    }

    pub fn get(&self, fd: Fd) -> Option<&RuntimeObject> {
        self.entries.get(&fd)
    }

    pub fn close(&mut self, fd: Fd) -> Option<RuntimeObject> {
        self.entries.remove(&fd)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessState {
    pub process_id: ProcessId,
    pub fd_table: FdTable,
    pub approved: bool,
}

impl ProcessState {
    pub fn new(process_id: ProcessId) -> Self {
        Self {
            process_id,
            fd_table: FdTable::default(),
            approved: false,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeState {
    pub processes: BTreeMap<ProcessId, ProcessState>,
}

impl RuntimeState {
    pub fn process_mut(&mut self, process_id: &ProcessId) -> Option<&mut ProcessState> {
        self.processes.get_mut(process_id)
    }

    pub fn insert_process(&mut self, process: ProcessState) {
        self.processes.insert(process.process_id.clone(), process);
    }
}
