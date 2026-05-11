use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::events::{
    AddressFamily, Endpoint, Event, Fd, PipeId, ProcessId, SocketLevel, SocketOption,
    SocketProtocol, SocketType, StartTime, Timestamp,
};

use super::Scenario;

#[derive(Debug)]
pub enum ScenarioFileError {
    Io(std::io::Error),
    Parse(serde_yaml::Error),
}

impl fmt::Display for ScenarioFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "failed to read scenario file: {err}"),
            Self::Parse(err) => write!(f, "failed to parse scenario file: {err}"),
        }
    }
}

impl std::error::Error for ScenarioFileError {}

impl From<std::io::Error> for ScenarioFileError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_yaml::Error> for ScenarioFileError {
    fn from(value: serde_yaml::Error) -> Self {
        Self::Parse(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct ScenarioDocument {
    name: String,
    events: Vec<ScenarioEvent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ScenarioEvent {
    AgentLaunch {
        process: ScenarioProcess,
        command: Vec<String>,
        at: u64,
    },
    ApprovalGranted {
        process: ScenarioProcess,
        reason: String,
        at: u64,
    },
    Fork {
        parent: ScenarioProcess,
        child: ScenarioProcess,
        at: u64,
    },
    Exec {
        parent: ScenarioProcess,
        child: ScenarioProcess,
        program: PathBuf,
        argv: Vec<String>,
        at: u64,
    },
    Open {
        process: ScenarioProcess,
        fd: i32,
        path: PathBuf,
        at: u64,
    },
    Pipe {
        process: ScenarioProcess,
        pipe: u64,
        read_fd: i32,
        write_fd: i32,
        at: u64,
    },
    Dup {
        process: ScenarioProcess,
        from_fd: i32,
        to_fd: i32,
        at: u64,
    },
    Close {
        process: ScenarioProcess,
        fd: i32,
        at: u64,
    },
    Read {
        process: ScenarioProcess,
        fd: i32,
        len: usize,
        at: u64,
    },
    Write {
        process: ScenarioProcess,
        fd: i32,
        len: usize,
        at: u64,
    },
    Connect {
        process: ScenarioProcess,
        fd: i32,
        endpoint: ScenarioEndpoint,
        at: u64,
    },
    Recv {
        process: ScenarioProcess,
        fd: i32,
        len: usize,
        at: u64,
    },
    Send {
        process: ScenarioProcess,
        fd: i32,
        len: usize,
        at: u64,
    },
    SocketCreate {
        process: ScenarioProcess,
        fd: i32,
        family: ScenarioAddressFamily,
        socket_type: ScenarioSocketType,
        protocol: Option<ScenarioSocketProtocol>,
        at: u64,
    },
    SetSockOpt {
        process: ScenarioProcess,
        fd: i32,
        level: ScenarioSocketLevel,
        option: ScenarioSocketOption,
        at: u64,
    },
    Splice {
        process: ScenarioProcess,
        from_fd: i32,
        to_fd: i32,
        len: usize,
        at: u64,
    },
    Exit {
        process: ScenarioProcess,
        at: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct ScenarioProcess {
    pid: u32,
    start_time: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct ScenarioEndpoint {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ScenarioAddressFamily {
    AfAlg,
    Other(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ScenarioSocketType {
    Stream,
    Datagram,
    SeqPacket,
    Other(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ScenarioSocketProtocol {
    Default,
    Other(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ScenarioSocketLevel {
    SolAlg,
    Other(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ScenarioSocketOption {
    AlgSetKey,
    AlgSetAeadAssoclen,
    AlgSetAeadAuthsize,
    Other(String),
}

pub fn load_yaml_file(path: impl AsRef<Path>) -> Result<Scenario, ScenarioFileError> {
    let input = std::fs::read_to_string(path)?;
    load_yaml_str(&input)
}

pub fn load_yaml_str(input: &str) -> Result<Scenario, ScenarioFileError> {
    let document: ScenarioDocument = serde_yaml::from_str(input)?;
    Ok(document.into_scenario())
}

impl ScenarioDocument {
    fn into_scenario(self) -> Scenario {
        let events = self
            .events
            .into_iter()
            .map(ScenarioEvent::into_event)
            .collect();

        Scenario::new(self.name, events)
    }
}

impl ScenarioEvent {
    fn into_event(self) -> Event {
        match self {
            Self::AgentLaunch {
                process,
                command,
                at,
            } => Event::AgentLaunch {
                process: process.into(),
                command,
                at: Timestamp(at),
            },
            Self::ApprovalGranted {
                process,
                reason,
                at,
            } => Event::ApprovalGranted {
                process: process.into(),
                reason,
                at: Timestamp(at),
            },
            Self::Fork { parent, child, at } => Event::Fork {
                parent: parent.into(),
                child: child.into(),
                at: Timestamp(at),
            },
            Self::Exec {
                parent,
                child,
                program,
                argv,
                at,
            } => Event::Exec {
                parent: parent.into(),
                child: child.into(),
                program,
                argv,
                at: Timestamp(at),
            },
            Self::Open {
                process,
                fd,
                path,
                at,
            } => Event::Open {
                process: process.into(),
                fd: Fd(fd),
                path,
                at: Timestamp(at),
            },
            Self::Pipe {
                process,
                pipe,
                read_fd,
                write_fd,
                at,
            } => Event::Pipe {
                process: process.into(),
                pipe: PipeId(pipe),
                read_fd: Fd(read_fd),
                write_fd: Fd(write_fd),
                at: Timestamp(at),
            },
            Self::Dup {
                process,
                from_fd,
                to_fd,
                at,
            } => Event::Dup {
                process: process.into(),
                from_fd: Fd(from_fd),
                to_fd: Fd(to_fd),
                at: Timestamp(at),
            },
            Self::Close { process, fd, at } => Event::Close {
                process: process.into(),
                fd: Fd(fd),
                at: Timestamp(at),
            },
            Self::Read {
                process,
                fd,
                len,
                at,
            } => Event::Read {
                process: process.into(),
                fd: Fd(fd),
                len,
                at: Timestamp(at),
            },
            Self::Write {
                process,
                fd,
                len,
                at,
            } => Event::Write {
                process: process.into(),
                fd: Fd(fd),
                len,
                at: Timestamp(at),
            },
            Self::Connect {
                process,
                fd,
                endpoint,
                at,
            } => Event::Connect {
                process: process.into(),
                fd: Fd(fd),
                endpoint: endpoint.into(),
                at: Timestamp(at),
            },
            Self::Recv {
                process,
                fd,
                len,
                at,
            } => Event::Recv {
                process: process.into(),
                fd: Fd(fd),
                len,
                at: Timestamp(at),
            },
            Self::Send {
                process,
                fd,
                len,
                at,
            } => Event::Send {
                process: process.into(),
                fd: Fd(fd),
                len,
                at: Timestamp(at),
            },
            Self::SocketCreate {
                process,
                fd,
                family,
                socket_type,
                protocol,
                at,
            } => Event::SocketCreate {
                process: process.into(),
                fd: Fd(fd),
                family: family.into(),
                socket_type: socket_type.into(),
                protocol: protocol
                    .map(SocketProtocol::from)
                    .unwrap_or(SocketProtocol::Default),
                at: Timestamp(at),
            },
            Self::SetSockOpt {
                process,
                fd,
                level,
                option,
                at,
            } => Event::SetSockOpt {
                process: process.into(),
                fd: Fd(fd),
                level: level.into(),
                option: option.into(),
                at: Timestamp(at),
            },
            Self::Splice {
                process,
                from_fd,
                to_fd,
                len,
                at,
            } => Event::Splice {
                process: process.into(),
                from_fd: Fd(from_fd),
                to_fd: Fd(to_fd),
                len,
                at: Timestamp(at),
            },
            Self::Exit { process, at } => Event::Exit {
                process: process.into(),
                at: Timestamp(at),
            },
        }
    }
}

impl From<ScenarioProcess> for ProcessId {
    fn from(value: ScenarioProcess) -> Self {
        Self::new(value.pid, StartTime(value.start_time))
    }
}

impl From<ScenarioEndpoint> for Endpoint {
    fn from(value: ScenarioEndpoint) -> Self {
        Self::tcp(value.host, value.port)
    }
}

impl From<ScenarioAddressFamily> for AddressFamily {
    fn from(value: ScenarioAddressFamily) -> Self {
        match value {
            ScenarioAddressFamily::AfAlg => Self::AfAlg,
            ScenarioAddressFamily::Other(value) => Self::Other(value),
        }
    }
}

impl From<ScenarioSocketType> for SocketType {
    fn from(value: ScenarioSocketType) -> Self {
        match value {
            ScenarioSocketType::Stream => Self::Stream,
            ScenarioSocketType::Datagram => Self::Datagram,
            ScenarioSocketType::SeqPacket => Self::SeqPacket,
            ScenarioSocketType::Other(value) => Self::Other(value),
        }
    }
}

impl From<ScenarioSocketProtocol> for SocketProtocol {
    fn from(value: ScenarioSocketProtocol) -> Self {
        match value {
            ScenarioSocketProtocol::Default => Self::Default,
            ScenarioSocketProtocol::Other(value) => Self::Other(value),
        }
    }
}

impl From<ScenarioSocketLevel> for SocketLevel {
    fn from(value: ScenarioSocketLevel) -> Self {
        match value {
            ScenarioSocketLevel::SolAlg => Self::SolAlg,
            ScenarioSocketLevel::Other(value) => Self::Other(value),
        }
    }
}

impl From<ScenarioSocketOption> for SocketOption {
    fn from(value: ScenarioSocketOption) -> Self {
        match value {
            ScenarioSocketOption::AlgSetKey => Self::AlgSetKey,
            ScenarioSocketOption::AlgSetAeadAssoclen => Self::AlgSetAeadAssoclen,
            ScenarioSocketOption::AlgSetAeadAuthsize => Self::AlgSetAeadAuthsize,
            ScenarioSocketOption::Other(value) => Self::Other(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::events::{AddressFamily, Event, SocketLevel};
    use crate::policy::{DecisionKind, PolicyId};
    use crate::scenarios::ReplayWarningKind;
    use crate::scenarios::ScenarioRunner;

    use super::{load_yaml_file, load_yaml_str};

    #[test]
    fn loads_secret_exfil_yaml_and_replays_it() {
        let scenario = load_yaml_file("scenarios/secret_exfil.yaml").unwrap();

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(scenario.name, "secret_exfil");
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Block);
        assert_eq!(
            outcome.enforcement.decision.violations[0].policy,
            PolicyId::SecretToNetwork
        );
        assert_eq!(outcome.explanations[0].path.len(), 4);
    }

    #[test]
    fn loads_boundary_events_from_yaml() {
        let scenario = load_yaml_str(
            r#"
name: copy_fail_boundary_events
events:
  - type: socket_create
    process:
      pid: 400
      start_time: 3000
    fd: 3
    family: af_alg
    socket_type: seq_packet
    protocol: default
    at: 1
  - type: set_sock_opt
    process:
      pid: 400
      start_time: 3000
    fd: 3
    level: sol_alg
    option: alg_set_key
    at: 2
  - type: splice
    process:
      pid: 400
      start_time: 3000
    from_fd: 4
    to_fd: 3
    len: 4096
    at: 3
"#,
        )
        .unwrap();

        assert_eq!(scenario.events.len(), 3);
        assert!(matches!(
            &scenario.events[0].event,
            Event::SocketCreate {
                family: AddressFamily::AfAlg,
                ..
            }
        ));
        assert!(matches!(
            &scenario.events[1].event,
            Event::SetSockOpt {
                level: SocketLevel::SolAlg,
                ..
            }
        ));
        assert!(matches!(&scenario.events[2].event, Event::Splice { .. }));
    }

    #[test]
    fn copy_fail_yaml_blocks_af_alg_socket_create() {
        let scenario = load_yaml_file("scenarios/copy_fail.yaml").unwrap();

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(scenario.name, "copy_fail");
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Block);
        assert_eq!(
            outcome.enforcement.decision.violations[0].policy,
            PolicyId::CopyFailAfAlgPattern
        );
        assert!(matches!(
            &outcome.enforcement.decision.violations[0].sink_event.event,
            Event::SocketCreate {
                family: AddressFamily::AfAlg,
                ..
            }
        ));
    }

    #[test]
    fn prompt_shell_yaml_blocks_without_approval() {
        let scenario = load_yaml_file("scenarios/prompt_shell_block.yaml").unwrap();

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(scenario.name, "prompt_shell_block");
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Block);
        assert_eq!(
            outcome.enforcement.decision.violations[0].policy,
            PolicyId::PromptToShellWithoutApproval
        );
        assert!(matches!(
            &outcome.enforcement.decision.violations[0].sink_event.event,
            Event::Exec { program, .. } if program == &std::path::PathBuf::from("/bin/bash")
        ));
        assert_eq!(outcome.explanations[0].path.len(), 1);
    }

    #[test]
    fn prompt_shell_yaml_allows_scoped_approval() {
        let scenario = load_yaml_file("scenarios/prompt_shell_approved.yaml").unwrap();

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(scenario.name, "prompt_shell_approved");
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Allow);
        assert!(outcome.enforcement.decision.violations.is_empty());
    }

    #[test]
    fn external_executable_write_yaml_blocks() {
        let scenario = load_yaml_file("scenarios/external_executable_write.yaml").unwrap();

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(scenario.name, "external_executable_write");
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Block);
        assert_eq!(
            outcome.enforcement.decision.violations[0].policy,
            PolicyId::ExternalToExecutableWrite
        );
        assert!(matches!(
            &outcome.enforcement.decision.violations[0].sink_event.event,
            Event::Write { process, fd, .. } if process.pid == 720 && fd.0 == 4
        ));
        assert_eq!(outcome.explanations[0].path.len(), 2);
    }

    #[test]
    fn benign_external_download_yaml_is_allowed() {
        let scenario = load_yaml_file("scenarios/benign_external_download.yaml").unwrap();

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(scenario.name, "benign_external_download");
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Allow);
        assert!(outcome.enforcement.decision.violations.is_empty());
    }

    #[test]
    fn sandbox_escape_docker_socket_yaml_blocks() {
        let scenario = load_yaml_file("scenarios/sandbox_escape_docker_socket.yaml").unwrap();

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(scenario.name, "sandbox_escape_docker_socket");
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Block);
        assert_eq!(
            outcome.enforcement.decision.violations[0].policy,
            PolicyId::PromptToContainerRuntimeSocket
        );
        assert!(matches!(
            &outcome.enforcement.decision.violations[0].sink_event.event,
            Event::Open { path, .. } if path == &std::path::PathBuf::from("/var/run/docker.sock")
        ));
        assert!(outcome.explanations[0].path.is_empty());
    }

    #[test]
    fn benign_tmp_socket_file_yaml_is_allowed() {
        let scenario = load_yaml_file("scenarios/benign_tmp_socket_file.yaml").unwrap();

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(scenario.name, "benign_tmp_socket_file");
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Allow);
        assert!(outcome.enforcement.decision.violations.is_empty());
    }

    #[test]
    fn malformed_missing_fd_yaml_warns_and_continues() {
        let scenario = load_yaml_file("scenarios/malformed_missing_fd.yaml").unwrap();

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(scenario.name, "malformed_missing_fd");
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Allow);
        assert!(outcome.enforcement.decision.violations.is_empty());
        assert!(outcome.graph.edges.is_empty());
        assert_eq!(outcome.graph.nodes.len(), 1);
        assert_eq!(outcome.warnings.len(), 1);
        assert_eq!(outcome.warnings[0].sequence, 1);
        assert_eq!(outcome.warnings[0].kind, ReplayWarningKind::MissingFd);
        assert!(outcome.warnings[0].message.contains("missing fd mapping"));
    }

    #[test]
    fn benign_send_yaml_is_allowed() {
        let scenario = load_yaml_file("scenarios/benign_send.yaml").unwrap();

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(scenario.name, "benign_send");
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Allow);
        assert!(outcome.enforcement.decision.violations.is_empty());
    }

    #[test]
    fn benign_socket_yaml_is_allowed() {
        let scenario = load_yaml_file("scenarios/benign_socket.yaml").unwrap();

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(scenario.name, "benign_socket");
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Allow);
        assert!(outcome.enforcement.decision.violations.is_empty());
    }
}
