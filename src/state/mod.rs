use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::events::{Endpoint, Fd, PipeId, ProcessId, SocketId};

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
    socket_endpoints: BTreeMap<SocketId, Endpoint>,
    next_socket_id: u64,
}

impl RuntimeState {
    pub fn ensure_process(&mut self, process_id: &ProcessId) -> &mut ProcessState {
        self.processes
            .entry(process_id.clone())
            .or_insert_with(|| ProcessState::new(process_id.clone()))
    }

    pub fn process_mut(&mut self, process_id: &ProcessId) -> Option<&mut ProcessState> {
        self.processes.get_mut(process_id)
    }

    pub fn insert_process(&mut self, process: ProcessState) {
        self.processes.insert(process.process_id.clone(), process);
    }

    pub fn approve_process(&mut self, process_id: &ProcessId) {
        self.ensure_process(process_id).approved = true;
    }

    pub fn fork_process(&mut self, parent: &ProcessId, child: &ProcessId) -> Result<(), String> {
        let parent_state = self
            .processes
            .get(parent)
            .cloned()
            .ok_or_else(|| format!("unknown fork parent: {:?}", parent))?;
        let mut child_state = parent_state;
        child_state.process_id = child.clone();
        self.insert_process(child_state);
        Ok(())
    }

    pub fn exec_process(&mut self, parent: &ProcessId, child: &ProcessId) -> Result<(), String> {
        let parent_state = self
            .processes
            .get(parent)
            .cloned()
            .ok_or_else(|| format!("unknown exec parent: {:?}", parent))?;
        let mut child_state = parent_state;
        child_state.process_id = child.clone();
        self.insert_process(child_state);
        Ok(())
    }

    pub fn map_open_file(&mut self, process: &ProcessId, fd: Fd, path: PathBuf) {
        self.ensure_process(process)
            .fd_table
            .insert(fd, RuntimeObject::File { path });
    }

    pub fn map_pipe(&mut self, process: &ProcessId, pipe: PipeId, read_fd: Fd, write_fd: Fd) {
        let process_state = self.ensure_process(process);
        process_state
            .fd_table
            .insert(read_fd, RuntimeObject::PipeReadEnd { pipe });
        process_state
            .fd_table
            .insert(write_fd, RuntimeObject::PipeWriteEnd { pipe });
    }

    pub fn dup_fd(&mut self, process: &ProcessId, from_fd: Fd, to_fd: Fd) -> Result<(), String> {
        let object = self.lookup_fd(process, from_fd)?.clone();
        self.ensure_process(process).fd_table.insert(to_fd, object);
        Ok(())
    }

    pub fn close_fd(&mut self, process: &ProcessId, fd: Fd) -> Result<(), String> {
        let closed = self.ensure_process(process).fd_table.close(fd);
        if closed.is_none() {
            return Err(format!("missing close fd: {:?} {:?}", process, fd));
        }
        Ok(())
    }

    pub fn connect_socket(&mut self, process: &ProcessId, fd: Fd, endpoint: Endpoint) -> SocketId {
        self.next_socket_id += 1;
        let socket_id = SocketId(self.next_socket_id);
        self.socket_endpoints.insert(socket_id, endpoint);
        self.ensure_process(process)
            .fd_table
            .insert(fd, RuntimeObject::Socket { socket: socket_id });
        socket_id
    }

    pub fn lookup_fd(&self, process: &ProcessId, fd: Fd) -> Result<&RuntimeObject, String> {
        self.processes
            .get(process)
            .ok_or_else(|| format!("unknown process for fd lookup: {:?}", process))?
            .fd_table
            .get(fd)
            .ok_or_else(|| format!("missing fd mapping: {:?} {:?}", process, fd))
    }

    pub fn socket_endpoint(&self, socket: SocketId) -> Result<&Endpoint, String> {
        self.socket_endpoints
            .get(&socket)
            .ok_or_else(|| format!("missing endpoint for socket: {:?}", socket))
    }
}
