use std::path::Path;

use crate::events::{AddressFamily, Event, ObservedEvent};
use crate::graph::{EdgeId, NodeId};
use crate::labels::{Label, LabelState};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PolicyId {
    ExternalToExec,
    SecretToNetwork,
    PromptToShellWithoutApproval,
    ExternalToExecutableWrite,
    PromptToContainerRuntimeSocket,
    CopyFailAfAlgPattern,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DecisionKind {
    Allow,
    Alert,
    RequireApproval,
    Block,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Violation {
    pub policy: PolicyId,
    pub sink_event: ObservedEvent,
    pub sink_edge: Option<EdgeId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decision {
    pub kind: DecisionKind,
    pub violations: Vec<Violation>,
}

pub fn check_external_to_exec(
    labels: &LabelState,
    process_node: NodeId,
    sink_event: &ObservedEvent,
    sink_edge: EdgeId,
) -> Option<Violation> {
    if labels.has_label(process_node, Label::External) {
        return Some(Violation {
            policy: PolicyId::ExternalToExec,
            sink_event: sink_event.clone(),
            sink_edge: Some(sink_edge),
        });
    }

    None
}

pub fn check_secret_to_network(
    labels: &LabelState,
    endpoint_node: NodeId,
    sink_event: &ObservedEvent,
    sink_edge: EdgeId,
) -> Option<Violation> {
    if labels.has_label(endpoint_node, Label::Secret) {
        return Some(Violation {
            policy: PolicyId::SecretToNetwork,
            sink_event: sink_event.clone(),
            sink_edge: Some(sink_edge),
        });
    }

    None
}

pub fn check_prompt_to_shell_without_approval(
    labels: &LabelState,
    process_node: NodeId,
    sink_event: &ObservedEvent,
    sink_edge: EdgeId,
) -> Option<Violation> {
    let Event::Exec { program, argv, .. } = &sink_event.event else {
        return None;
    };

    if !is_shell_or_interpreter(program, argv) {
        return None;
    }

    if labels.has_label(process_node, Label::Prompt)
        && !labels.has_label(process_node, Label::Approved)
    {
        return Some(Violation {
            policy: PolicyId::PromptToShellWithoutApproval,
            sink_event: sink_event.clone(),
            sink_edge: Some(sink_edge),
        });
    }

    None
}

pub fn check_external_to_executable_write(
    labels: &LabelState,
    file_node: NodeId,
    path: &Path,
    sink_event: &ObservedEvent,
    sink_edge: EdgeId,
) -> Option<Violation> {
    if !matches!(sink_event.event, Event::Write { .. }) {
        return None;
    }

    if labels.has_label(file_node, Label::External) && is_executable_path(path) {
        return Some(Violation {
            policy: PolicyId::ExternalToExecutableWrite,
            sink_event: sink_event.clone(),
            sink_edge: Some(sink_edge),
        });
    }

    None
}

pub fn check_prompt_to_container_runtime_socket(
    labels: &LabelState,
    process_node: NodeId,
    path: &Path,
    sink_event: &ObservedEvent,
) -> Option<Violation> {
    if !matches!(sink_event.event, Event::Open { .. }) {
        return None;
    }

    if labels.has_label(process_node, Label::Prompt) && is_container_runtime_socket(path) {
        return Some(Violation {
            policy: PolicyId::PromptToContainerRuntimeSocket,
            sink_event: sink_event.clone(),
            sink_edge: None,
        });
    }

    None
}

pub fn check_copy_fail_af_alg_pattern(
    labels: &LabelState,
    process_node: NodeId,
    sink_event: &ObservedEvent,
) -> Option<Violation> {
    let Event::SocketCreate {
        family: AddressFamily::AfAlg,
        ..
    } = &sink_event.event
    else {
        return None;
    };

    if labels.has_label(process_node, Label::Prompt) {
        return Some(Violation {
            policy: PolicyId::CopyFailAfAlgPattern,
            sink_event: sink_event.clone(),
            sink_edge: None,
        });
    }

    None
}

fn is_executable_path(path: &Path) -> bool {
    path.starts_with("/bin")
        || path.starts_with("/sbin")
        || path.starts_with("/usr/bin")
        || path.starts_with("/usr/sbin")
        || path.starts_with("/usr/local/bin")
        || path.starts_with("/usr/local/sbin")
}

fn is_container_runtime_socket(path: &Path) -> bool {
    matches!(
        path.to_str(),
        Some(
            "/var/run/docker.sock"
                | "/run/docker.sock"
                | "/run/containerd/containerd.sock"
                | "/var/run/containerd/containerd.sock"
                | "/run/crio/crio.sock"
                | "/var/run/crio/crio.sock"
                | "/run/podman/podman.sock"
                | "/var/run/podman/podman.sock"
        )
    )
}

fn is_shell_or_interpreter(program: &Path, argv: &[String]) -> bool {
    executable_name(program).is_some_and(is_shell_or_interpreter_name)
        || argv.iter().any(|arg| {
            let path = Path::new(arg);
            executable_name(path).is_some_and(is_shell_or_interpreter_name)
                || is_shell_or_interpreter_name(arg)
        })
}

fn executable_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

fn is_shell_or_interpreter_name(name: &str) -> bool {
    matches!(
        name,
        "bash"
            | "sh"
            | "zsh"
            | "dash"
            | "fish"
            | "python"
            | "python3"
            | "node"
            | "ruby"
            | "perl"
            | "php"
            | "lua"
    )
}

pub fn decide(violations: Vec<Violation>) -> Decision {
    let kind = if violations.is_empty() {
        DecisionKind::Allow
    } else {
        DecisionKind::Block
    };

    Decision { kind, violations }
}
