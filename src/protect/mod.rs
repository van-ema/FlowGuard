use crate::scenarios::{Scenario, ScenarioOutcome};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectRun {
    pub scenario: Scenario,
    pub outcome: ScenarioOutcome,
    pub exit_code: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PtraceProtector {
    command: Vec<String>,
}

impl PtraceProtector {
    pub fn new(command: Vec<String>) -> Self {
        Self { command }
    }

    pub fn run(&self) -> Result<ProtectRun, String> {
        run_ptrace(self.command.clone())
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn run_ptrace(command: Vec<String>) -> Result<ProtectRun, String> {
    linux::run(command)
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn run_ptrace(_command: Vec<String>) -> Result<ProtectRun, String> {
    Err("ptrace protect is currently supported only on Linux x86_64 and AArch64".to_string())
}
