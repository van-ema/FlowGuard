use std::fmt;
use std::path::{Path, PathBuf};

use crate::scenarios::Scenario;
use crate::scenarios::demo;
use crate::scenarios::file::{ScenarioFileError, load_yaml_file};

pub mod strace;
pub use strace::StraceSource;

/// Boundary between event collection and the provenance engine.
///
/// Event sources own acquisition and normalization. The runner should not care
/// whether events came from a YAML fixture, a demo harness, eBPF, Falco, Tracee,
/// or another collector. For the MVP the source materializes a deterministic
/// `Scenario`; live sources can later implement the same boundary with buffered
/// normalized events.
pub trait EventSource {
    /// Load or synthesize normalized Flowguard events for one replayable run.
    fn load_scenario(&self) -> Result<Scenario, EventSourceError>;
}

#[derive(Debug)]
pub enum EventSourceError {
    ScenarioFile(ScenarioFileError),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    CommandIo {
        program: String,
        source: std::io::Error,
    },
    RawTraceIo {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for EventSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScenarioFile(err) => write!(f, "{err}"),
            Self::Io { path, source } => {
                write!(
                    f,
                    "failed to read event source {}: {source}",
                    path.display()
                )
            }
            Self::CommandIo { program, source } => {
                write!(f, "failed to run event source command {program}: {source}")
            }
            Self::RawTraceIo { path, source } => {
                write!(f, "failed to write raw strace {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for EventSourceError {}

impl From<ScenarioFileError> for EventSourceError {
    fn from(value: ScenarioFileError) -> Self {
        Self::ScenarioFile(value)
    }
}

/// Reads a scenario YAML file and converts it into normalized domain events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YamlScenarioSource {
    path: PathBuf,
}

impl YamlScenarioSource {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl EventSource for YamlScenarioSource {
    fn load_scenario(&self) -> Result<Scenario, EventSourceError> {
        load_yaml_file(&self.path).map_err(EventSourceError::from)
    }
}

/// Synthetic live-ish demo source for the MVP secret-exfiltration story.
///
/// It reads the fake secret fixture only to size the observed `Read`/`Write`/
/// `Send` events. It does not execute `cat`, `curl`, or perform network I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DemoSecretExfilSource {
    fixture_path: PathBuf,
}

impl DemoSecretExfilSource {
    pub fn new(fixture_path: impl Into<PathBuf>) -> Self {
        Self {
            fixture_path: fixture_path.into(),
        }
    }

    pub fn repo_default() -> Self {
        Self::new(Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/home/.ssh/id_rsa"))
    }
}

impl EventSource for DemoSecretExfilSource {
    fn load_scenario(&self) -> Result<Scenario, EventSourceError> {
        let fixture = std::fs::read(&self.fixture_path).map_err(|source| EventSourceError::Io {
            path: self.fixture_path.clone(),
            source,
        })?;
        Ok(demo::secret_exfil(fixture.len()))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::policy::{DecisionKind, PolicyId};
    use crate::scenarios::ScenarioRunner;

    use super::{DemoSecretExfilSource, EventSource, YamlScenarioSource};

    fn scenario_path(path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
    }

    #[test]
    fn yaml_source_loads_replayable_scenario() {
        let source = YamlScenarioSource::new(scenario_path("scenarios/secret_exfil.yaml"));

        let scenario = source.load_scenario().unwrap();
        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(scenario.name, "secret_exfil");
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Block);
        assert_eq!(
            outcome.enforcement.decision.violations[0].policy,
            PolicyId::SecretToNetwork
        );
    }

    #[test]
    fn demo_source_loads_secret_exfil_scenario() {
        let source = DemoSecretExfilSource::repo_default();

        let scenario = source.load_scenario().unwrap();
        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(scenario.name, "demo_secret_exfil");
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Block);
        assert_eq!(
            outcome.enforcement.decision.violations[0].policy,
            PolicyId::SecretToNetwork
        );
    }
}
