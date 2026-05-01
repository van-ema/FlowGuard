use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::events::{Endpoint, Event, Fd, PipeId, ProcessId, StartTime, Timestamp};

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

#[cfg(test)]
mod tests {
    use crate::policy::{DecisionKind, PolicyId};
    use crate::scenarios::ScenarioRunner;

    use super::load_yaml_file;

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
}
