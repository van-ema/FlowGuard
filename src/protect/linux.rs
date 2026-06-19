use std::collections::BTreeMap;
use std::ffi::{CString, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use std::fs;
use std::mem;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::ptr;

use crate::events::{Endpoint, Event, Fd, PipeId, ProcessId, StartTime, Timestamp};
use crate::protect::ProtectRun;
use crate::scenarios::{ReplaySession, Scenario};
use crate::state::RuntimeObject;

type Pid = c_int;

const PTRACE_TRACEME: c_uint = 0;
const PTRACE_PEEKDATA: c_uint = 2;
#[cfg(target_arch = "x86_64")]
const PTRACE_GETREGS: c_uint = 12;
const PTRACE_SYSCALL: c_uint = 24;
const PTRACE_SETOPTIONS: c_uint = 0x4200;
const PTRACE_GETEVENTMSG: c_uint = 0x4201;
const PTRACE_GETREGSET: c_uint = 0x4204;
const NT_PRSTATUS: c_ulong = 1;

const PTRACE_O_TRACESYSGOOD: c_ulong = 0x00000001;
const PTRACE_O_TRACEFORK: c_ulong = 0x00000002;
const PTRACE_O_TRACEVFORK: c_ulong = 0x00000004;
const PTRACE_O_TRACECLONE: c_ulong = 0x00000008;
const PTRACE_O_TRACEEXEC: c_ulong = 0x00000010;
const PTRACE_O_TRACEEXIT: c_ulong = 0x00000040;
const PTRACE_O_EXITKILL: c_ulong = 0x00100000;

const PTRACE_EVENT_FORK: c_int = 1;
const PTRACE_EVENT_VFORK: c_int = 2;
const PTRACE_EVENT_CLONE: c_int = 3;

const SIGTRAP: c_int = 5;
const SIGKILL: c_int = 9;
const SIGSTOP: c_int = 19;
const TRACESYSGOOD_SIGTRAP: c_int = SIGTRAP | 0x80;
const WAIT_ALL_TRACED_THREADS: c_int = 0x40000000;

const AF_UNSPEC: u16 = 0;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[cfg(target_arch = "x86_64")]
const SYS_READ: u64 = 0;
#[cfg(target_arch = "x86_64")]
const SYS_WRITE: u64 = 1;
#[cfg(target_arch = "x86_64")]
const SYS_OPEN: u64 = 2;
#[cfg(target_arch = "x86_64")]
const SYS_CLOSE: u64 = 3;
#[cfg(target_arch = "x86_64")]
const SYS_PIPE: u64 = 22;
#[cfg(target_arch = "x86_64")]
const SYS_DUP: u64 = 32;
#[cfg(target_arch = "x86_64")]
const SYS_DUP2: u64 = 33;
#[cfg(target_arch = "x86_64")]
const SYS_CONNECT: u64 = 42;
#[cfg(target_arch = "x86_64")]
const SYS_SENDTO: u64 = 44;
#[cfg(target_arch = "x86_64")]
const SYS_RECVFROM: u64 = 45;
#[cfg(target_arch = "x86_64")]
const SYS_SENDMSG: u64 = 46;
#[cfg(target_arch = "x86_64")]
const SYS_RECVMSG: u64 = 47;
#[cfg(target_arch = "x86_64")]
const SYS_OPENAT: u64 = 257;
#[cfg(target_arch = "x86_64")]
const SYS_DUP3: u64 = 292;
#[cfg(target_arch = "x86_64")]
const SYS_PIPE2: u64 = 293;

#[cfg(target_arch = "aarch64")]
const SYS_DUP: u64 = 23;
#[cfg(target_arch = "aarch64")]
const SYS_DUP3: u64 = 24;
#[cfg(target_arch = "aarch64")]
const SYS_OPENAT: u64 = 56;
#[cfg(target_arch = "aarch64")]
const SYS_CLOSE: u64 = 57;
#[cfg(target_arch = "aarch64")]
const SYS_PIPE2: u64 = 59;
#[cfg(target_arch = "aarch64")]
const SYS_READ: u64 = 63;
#[cfg(target_arch = "aarch64")]
const SYS_WRITE: u64 = 64;
#[cfg(target_arch = "aarch64")]
const SYS_CONNECT: u64 = 203;
#[cfg(target_arch = "aarch64")]
const SYS_SENDTO: u64 = 206;
#[cfg(target_arch = "aarch64")]
const SYS_RECVFROM: u64 = 207;
#[cfg(target_arch = "aarch64")]
const SYS_SENDMSG: u64 = 211;
#[cfg(target_arch = "aarch64")]
const SYS_RECVMSG: u64 = 212;

#[cfg(target_arch = "aarch64")]
const SYS_OPEN: u64 = u64::MAX;
#[cfg(target_arch = "aarch64")]
const SYS_PIPE: u64 = u64::MAX - 1;
#[cfg(target_arch = "aarch64")]
const SYS_DUP2: u64 = u64::MAX - 2;

unsafe extern "C" {
    fn fork() -> Pid;
    fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int;
    fn raise(signal: c_int) -> c_int;
    fn _exit(status: c_int) -> !;
    fn waitpid(pid: Pid, status: *mut c_int, options: c_int) -> Pid;
    fn ptrace(request: c_uint, pid: Pid, addr: *mut c_void, data: *mut c_void) -> c_long;
    fn kill(pid: Pid, signal: c_int) -> c_int;
    fn setpgid(pid: Pid, pgid: Pid) -> c_int;
    fn __errno_location() -> *mut c_int;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
#[cfg(target_arch = "x86_64")]
struct UserRegs {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
#[cfg(target_arch = "aarch64")]
struct UserRegs {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

#[repr(C)]
#[cfg(target_arch = "aarch64")]
struct Iovec {
    iov_base: *mut c_void,
    iov_len: usize,
}

#[derive(Clone, Debug, Default)]
struct ThreadState {
    entering_syscall: bool,
    pending: Option<PendingSyscall>,
}

#[derive(Clone, Debug)]
struct PendingSyscall {
    nr: u64,
    args: [u64; 6],
    open_path: Option<PathBuf>,
    connect_endpoint: Option<Endpoint>,
}

struct LiveTracer {
    root_pid: Pid,
    root_command: Vec<String>,
    replay: ReplaySession,
    events: Vec<crate::events::ObservedEvent>,
    processes: BTreeMap<Pid, ProcessId>,
    threads: BTreeMap<Pid, ThreadState>,
    next_start_time: u64,
    next_pipe_id: u64,
    exit_code: i32,
    blocked: bool,
}

pub fn run(command: Vec<String>) -> Result<ProtectRun, String> {
    if command.is_empty() {
        return Err("protect requires a command".to_string());
    }

    let cstrings = command
        .iter()
        .map(|arg| CString::new(arg.as_str()).map_err(|_| format!("argument contains NUL: {arg}")))
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv = cstrings
        .iter()
        .map(|arg| arg.as_ptr())
        .collect::<Vec<*const c_char>>();
    argv.push(ptr::null());

    let child = unsafe { fork() };
    if child < 0 {
        return Err(last_os_error("fork failed"));
    }

    if child == 0 {
        unsafe {
            let _ = setpgid(0, 0);
            if ptrace(PTRACE_TRACEME, 0, ptr::null_mut(), ptr::null_mut()) < 0 {
                _exit(127);
            }
            let _ = raise(SIGSTOP);
            execvp(argv[0], argv.as_ptr());
            _exit(127);
        }
    }

    LiveTracer::new(child, command).run()
}

impl LiveTracer {
    fn new(root_pid: Pid, root_command: Vec<String>) -> Self {
        Self {
            root_pid,
            root_command,
            replay: ReplaySession::new(),
            events: Vec::new(),
            processes: BTreeMap::new(),
            threads: BTreeMap::new(),
            next_start_time: 10_000,
            next_pipe_id: 1_000,
            exit_code: 0,
            blocked: false,
        }
    }

    fn run(mut self) -> Result<ProtectRun, String> {
        let mut status = 0;
        let waited = unsafe { waitpid(self.root_pid, &mut status, WAIT_ALL_TRACED_THREADS) };
        if waited < 0 {
            return Err(last_os_error("initial waitpid failed"));
        }
        if !wifstopped(status) {
            return Err(format!("child did not stop for tracing: status={status}"));
        }

        self.ensure_process(self.root_pid, Some(self.root_command.clone()));
        self.threads.entry(self.root_pid).or_default();
        set_ptrace_options(self.root_pid)?;
        resume_syscall(self.root_pid, 0)?;

        loop {
            let mut status = 0;
            let pid = unsafe { waitpid(-1, &mut status, WAIT_ALL_TRACED_THREADS) };
            if pid < 0 {
                let errno = current_errno();
                if errno == 10 {
                    break;
                }
                return Err(last_os_error("waitpid failed"));
            }

            if wifexited(status) {
                if pid == self.root_pid && !self.blocked {
                    self.exit_code = wexitstatus(status);
                }
                self.threads.remove(&pid);
                if self.threads.is_empty() {
                    break;
                }
                continue;
            }

            if wifsignaled(status) {
                if pid == self.root_pid && !self.blocked {
                    self.exit_code = 128 + wtermsig(status);
                }
                self.threads.remove(&pid);
                if self.threads.is_empty() {
                    break;
                }
                continue;
            }

            if !wifstopped(status) {
                continue;
            }

            let signal = wstopsig(status);
            if signal == TRACESYSGOOD_SIGTRAP {
                self.handle_syscall_stop(pid)?;
                if self.blocked {
                    self.kill_traced_processes();
                    self.drain_exits();
                    break;
                }
                resume_syscall(pid, 0)?;
                continue;
            }

            if signal == SIGTRAP {
                self.handle_ptrace_event(pid, ptrace_event(status))?;
                resume_syscall(pid, 0)?;
                continue;
            }

            // Child/clone stops are expected around fork events. Re-apply options
            // and suppress SIGSTOP so tracing continues deterministically.
            if signal == SIGSTOP {
                self.threads.entry(pid).or_default();
                let _ = set_ptrace_options(pid);
                resume_syscall(pid, 0)?;
                continue;
            }

            resume_syscall(pid, signal)?;
        }

        let outcome = self.replay.finish();
        let scenario = Scenario {
            name: "protect_ptrace".to_string(),
            events: self.events,
        };
        Ok(ProtectRun {
            scenario,
            outcome,
            exit_code: self.exit_code,
        })
    }

    fn handle_ptrace_event(&mut self, pid: Pid, event: c_int) -> Result<(), String> {
        if !matches!(
            event,
            PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK | PTRACE_EVENT_CLONE
        ) {
            self.threads.entry(pid).or_default();
            return Ok(());
        }

        let new_pid = get_event_msg(pid)? as Pid;
        let parent = self.ensure_process(pid, None);
        let child = self.next_process_identity(new_pid);
        self.processes.insert(new_pid, child.clone());
        self.threads.entry(new_pid).or_default();
        let _ = set_ptrace_options(new_pid);

        self.emit(Event::Fork {
            parent,
            child,
            at: self.next_timestamp(),
        });
        Ok(())
    }

    fn handle_syscall_stop(&mut self, pid: Pid) -> Result<(), String> {
        let regs = get_regs(pid)?;
        let entering = self.threads.entry(pid).or_default().entering_syscall;

        if !entering {
            let pending = self.pending_from_entry(pid, regs);
            self.threads.entry(pid).or_default().pending = Some(pending);
            self.threads.entry(pid).or_default().entering_syscall = true;
            self.check_blocking_send_on_entry(pid, regs)?;
            return Ok(());
        }

        let pending = self
            .threads
            .entry(pid)
            .or_default()
            .pending
            .take()
            .ok_or_else(|| format!("missing pending syscall for pid {pid}"))?;
        self.threads.entry(pid).or_default().entering_syscall = false;
        self.apply_syscall_exit(pid, pending, syscall_return(regs));
        Ok(())
    }

    fn pending_from_entry(&mut self, pid: Pid, regs: UserRegs) -> PendingSyscall {
        let nr = syscall_number(regs);
        let args = syscall_args(regs);
        let open_path = match nr {
            SYS_OPEN => read_c_string(pid, args[0]).map(PathBuf::from),
            SYS_OPENAT => read_c_string(pid, args[1]).map(PathBuf::from),
            _ => None,
        };
        let connect_endpoint = if nr == SYS_CONNECT {
            read_sockaddr_endpoint(pid, args[1], args[2] as usize)
        } else {
            None
        };

        PendingSyscall {
            nr,
            args,
            open_path,
            connect_endpoint,
        }
    }

    fn apply_syscall_exit(&mut self, pid: Pid, pending: PendingSyscall, ret: i64) {
        let process = self.ensure_process(pid, None);
        match pending.nr {
            SYS_OPEN | SYS_OPENAT => {
                if ret >= 0 {
                    if let Some(path) = pending.open_path {
                        self.emit(Event::Open {
                            process,
                            fd: Fd(ret as i32),
                            path,
                            at: self.next_timestamp(),
                        });
                    }
                }
            }
            SYS_PIPE | SYS_PIPE2 => {
                if ret == 0 {
                    if let Some((read_fd, write_fd)) = read_fd_pair(pid, pending.args[0]) {
                        let pipe = PipeId(self.next_pipe_id);
                        self.next_pipe_id += 1;
                        self.emit(Event::Pipe {
                            process,
                            pipe,
                            read_fd: Fd(read_fd),
                            write_fd: Fd(write_fd),
                            at: self.next_timestamp(),
                        });
                    }
                }
            }
            SYS_DUP | SYS_DUP2 | SYS_DUP3 => {
                if ret >= 0 {
                    self.emit(Event::Dup {
                        process,
                        from_fd: Fd(pending.args[0] as i32),
                        to_fd: Fd(ret as i32),
                        at: self.next_timestamp(),
                    });
                }
            }
            SYS_CLOSE => {
                if ret == 0 {
                    self.emit(Event::Close {
                        process,
                        fd: Fd(pending.args[0] as i32),
                        at: self.next_timestamp(),
                    });
                }
            }
            SYS_READ | SYS_RECVFROM | SYS_RECVMSG => {
                if ret > 0 {
                    let fd = Fd(pending.args[0] as i32);
                    if self.is_connected_socket(&process, fd) {
                        self.emit(Event::Recv {
                            process,
                            fd,
                            len: ret as usize,
                            at: self.next_timestamp(),
                        });
                    } else {
                        self.emit(Event::Read {
                            process,
                            fd,
                            len: ret as usize,
                            at: self.next_timestamp(),
                        });
                    }
                }
            }
            SYS_WRITE | SYS_SENDTO | SYS_SENDMSG => {
                if ret > 0 {
                    let fd = Fd(pending.args[0] as i32);
                    if self.is_connected_socket(&process, fd) {
                        self.emit(Event::Send {
                            process,
                            fd,
                            len: ret as usize,
                            at: self.next_timestamp(),
                        });
                    } else {
                        self.emit(Event::Write {
                            process,
                            fd,
                            len: ret as usize,
                            at: self.next_timestamp(),
                        });
                    }
                }
            }
            SYS_CONNECT => {
                if ret == 0 || ret == -115 {
                    if let Some(endpoint) = pending.connect_endpoint {
                        self.emit(Event::Connect {
                            process,
                            fd: Fd(pending.args[0] as i32),
                            endpoint,
                            at: self.next_timestamp(),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    fn check_blocking_send_on_entry(&mut self, pid: Pid, regs: UserRegs) -> Result<(), String> {
        let nr = syscall_number(regs);
        if !matches!(nr, SYS_WRITE | SYS_SENDTO | SYS_SENDMSG) {
            return Ok(());
        }

        let args = syscall_args(regs);
        let process = self.ensure_process(pid, None);
        let fd = Fd(args[0] as i32);
        if !self.is_connected_socket(&process, fd) {
            return Ok(());
        }

        let len = if nr == SYS_SENDMSG {
            1
        } else {
            args[2].max(1) as usize
        };
        self.emit(Event::Send {
            process,
            fd,
            len,
            at: self.next_timestamp(),
        });

        if self.replay.has_blocking_decision() {
            self.blocked = true;
            self.exit_code = 1;
        }

        Ok(())
    }

    fn ensure_process(&mut self, pid: Pid, command: Option<Vec<String>>) -> ProcessId {
        if let Some(process) = self.processes.get(&pid) {
            return process.clone();
        }

        let process = self.next_process_identity(pid);
        self.processes.insert(pid, process.clone());
        self.threads.entry(pid).or_default();
        self.emit(Event::AgentLaunch {
            process: process.clone(),
            command: command
                .filter(|command| !command.is_empty())
                .unwrap_or_else(|| vec![format!("observed-pid:{pid}")]),
            at: self.next_timestamp(),
        });
        process
    }

    fn next_process_identity(&mut self, pid: Pid) -> ProcessId {
        let start_time = read_proc_start_time(pid).unwrap_or_else(|| {
            let fallback = self.next_start_time;
            self.next_start_time += 10;
            fallback
        });
        ProcessId::new(pid as u32, StartTime(start_time))
    }

    fn emit(&mut self, event: Event) {
        let observed = crate::events::ObservedEvent {
            sequence: self.events.len() as u64,
            event,
        };
        self.replay.apply(&observed);
        self.events.push(observed);
    }

    fn next_timestamp(&self) -> Timestamp {
        Timestamp(self.events.len() as u64 + 1)
    }

    fn is_connected_socket(&self, process: &ProcessId, fd: Fd) -> bool {
        matches!(
            self.replay.resolve_fd(process, fd),
            Ok(RuntimeObject::Socket { .. })
        )
    }

    fn kill_traced_processes(&self) {
        unsafe {
            let _ = kill(-self.root_pid, SIGKILL);
        }
        for pid in self.threads.keys() {
            unsafe {
                let _ = kill(*pid, SIGKILL);
            }
        }
    }

    fn drain_exits(&mut self) {
        while !self.threads.is_empty() {
            let mut status = 0;
            let pid = unsafe { waitpid(-1, &mut status, WAIT_ALL_TRACED_THREADS) };
            if pid < 0 {
                break;
            }
            self.threads.remove(&pid);
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn syscall_args(regs: UserRegs) -> [u64; 6] {
    [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9]
}

#[cfg(target_arch = "aarch64")]
fn syscall_args(regs: UserRegs) -> [u64; 6] {
    [
        regs.regs[0],
        regs.regs[1],
        regs.regs[2],
        regs.regs[3],
        regs.regs[4],
        regs.regs[5],
    ]
}

#[cfg(target_arch = "x86_64")]
fn syscall_number(regs: UserRegs) -> u64 {
    regs.orig_rax
}

#[cfg(target_arch = "aarch64")]
fn syscall_number(regs: UserRegs) -> u64 {
    regs.regs[8]
}

#[cfg(target_arch = "x86_64")]
fn syscall_return(regs: UserRegs) -> i64 {
    regs.rax as i64
}

#[cfg(target_arch = "aarch64")]
fn syscall_return(regs: UserRegs) -> i64 {
    regs.regs[0] as i64
}

#[cfg(target_arch = "x86_64")]
fn get_regs(pid: Pid) -> Result<UserRegs, String> {
    let mut regs = UserRegs::default();
    let result = unsafe {
        ptrace(
            PTRACE_GETREGS,
            pid,
            ptr::null_mut(),
            &mut regs as *mut UserRegs as *mut c_void,
        )
    };
    if result < 0 {
        return Err(last_os_error("PTRACE_GETREGS failed"));
    }
    Ok(regs)
}

#[cfg(target_arch = "aarch64")]
fn get_regs(pid: Pid) -> Result<UserRegs, String> {
    let mut regs = UserRegs::default();
    let mut iovec = Iovec {
        iov_base: &mut regs as *mut UserRegs as *mut c_void,
        iov_len: mem::size_of::<UserRegs>(),
    };
    let result = unsafe {
        ptrace(
            PTRACE_GETREGSET,
            pid,
            NT_PRSTATUS as usize as *mut c_void,
            &mut iovec as *mut Iovec as *mut c_void,
        )
    };
    if result < 0 {
        return Err(last_os_error("PTRACE_GETREGSET failed"));
    }
    Ok(regs)
}

fn set_ptrace_options(pid: Pid) -> Result<(), String> {
    let options = PTRACE_O_TRACESYSGOOD
        | PTRACE_O_TRACEFORK
        | PTRACE_O_TRACEVFORK
        | PTRACE_O_TRACECLONE
        | PTRACE_O_TRACEEXEC
        | PTRACE_O_TRACEEXIT
        | PTRACE_O_EXITKILL;
    let result = unsafe {
        ptrace(
            PTRACE_SETOPTIONS,
            pid,
            ptr::null_mut(),
            options as *mut c_void,
        )
    };
    if result < 0 {
        return Err(last_os_error("PTRACE_SETOPTIONS failed"));
    }
    Ok(())
}

fn resume_syscall(pid: Pid, signal: c_int) -> Result<(), String> {
    let result = unsafe {
        ptrace(
            PTRACE_SYSCALL,
            pid,
            ptr::null_mut(),
            signal as usize as *mut c_void,
        )
    };
    if result < 0 {
        return Err(last_os_error("PTRACE_SYSCALL failed"));
    }
    Ok(())
}

fn get_event_msg(pid: Pid) -> Result<c_ulong, String> {
    let mut msg = 0;
    let result = unsafe {
        ptrace(
            PTRACE_GETEVENTMSG,
            pid,
            ptr::null_mut(),
            &mut msg as *mut c_ulong as *mut c_void,
        )
    };
    if result < 0 {
        return Err(last_os_error("PTRACE_GETEVENTMSG failed"));
    }
    Ok(msg)
}

fn read_c_string(pid: Pid, address: u64) -> Option<String> {
    let mut bytes = Vec::new();
    for offset in (0..4096).step_by(mem::size_of::<c_long>()) {
        let word = peek_data(pid, address.checked_add(offset as u64)?)?;
        for byte in word.to_ne_bytes() {
            if byte == 0 {
                return String::from_utf8(bytes).ok();
            }
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes).ok()
}

fn read_child_bytes(pid: Pid, address: u64, len: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut offset = 0;
    while offset < len {
        let word = peek_data(pid, address.checked_add(offset as u64)?)?;
        for byte in word.to_ne_bytes() {
            if bytes.len() == len {
                break;
            }
            bytes.push(byte);
        }
        offset += mem::size_of::<c_long>();
    }
    Some(bytes)
}

fn peek_data(pid: Pid, address: u64) -> Option<c_long> {
    unsafe {
        *__errno_location() = 0;
    }
    let word = unsafe {
        ptrace(
            PTRACE_PEEKDATA,
            pid,
            address as *mut c_void,
            ptr::null_mut(),
        )
    };
    if word == -1 && current_errno() != 0 {
        None
    } else {
        Some(word)
    }
}

fn read_fd_pair(pid: Pid, address: u64) -> Option<(i32, i32)> {
    let bytes = read_child_bytes(pid, address, 8)?;
    let read_fd = i32::from_ne_bytes(bytes[0..4].try_into().ok()?);
    let write_fd = i32::from_ne_bytes(bytes[4..8].try_into().ok()?);
    Some((read_fd, write_fd))
}

fn read_sockaddr_endpoint(pid: Pid, address: u64, len: usize) -> Option<Endpoint> {
    if address == 0 || len < 2 {
        return None;
    }
    let bytes = read_child_bytes(pid, address, len.min(128))?;
    let family = u16::from_ne_bytes(bytes.get(0..2)?.try_into().ok()?);
    match family {
        AF_UNSPEC => None,
        AF_INET if bytes.len() >= 8 => {
            let port = u16::from_be_bytes(bytes[2..4].try_into().ok()?);
            let host = format!("{}.{}.{}.{}", bytes[4], bytes[5], bytes[6], bytes[7]);
            Some(Endpoint::tcp(host, port))
        }
        AF_INET6 if bytes.len() >= 24 => {
            let port = u16::from_be_bytes(bytes[2..4].try_into().ok()?);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            Some(Endpoint::tcp(Ipv6Addr::from(octets).to_string(), port))
        }
        _ => None,
    }
}

fn read_proc_start_time(pid: Pid) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(") ")?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

fn current_errno() -> c_int {
    unsafe { *__errno_location() }
}

fn last_os_error(context: &str) -> String {
    format!("{context}: {}", std::io::Error::last_os_error())
}

fn wifexited(status: c_int) -> bool {
    status & 0x7f == 0
}

fn wexitstatus(status: c_int) -> i32 {
    (status >> 8) & 0xff
}

fn wifsignaled(status: c_int) -> bool {
    ((status & 0x7f) + 1) >> 1 > 0 && !wifstopped(status)
}

fn wtermsig(status: c_int) -> i32 {
    status & 0x7f
}

fn wifstopped(status: c_int) -> bool {
    status & 0xff == 0x7f
}

fn wstopsig(status: c_int) -> c_int {
    (status >> 8) & 0xff
}

fn ptrace_event(status: c_int) -> c_int {
    (status >> 16) & 0xffff
}

#[cfg(test)]
mod tests {
    use crate::events::Endpoint;

    use super::{AF_INET, read_proc_start_time};

    #[test]
    fn parses_current_process_start_time() {
        let pid = std::process::id() as i32;

        assert!(read_proc_start_time(pid).is_some());
    }

    #[test]
    fn sockaddr_ipv4_constants_match_linux_layout() {
        assert_eq!(AF_INET, 2);
        assert_eq!(Endpoint::tcp("127.0.0.1", 80).host, "127.0.0.1");
    }
}
