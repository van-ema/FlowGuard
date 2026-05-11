use std::env;
use std::process::ExitCode;

use flowguard::events::{Event, ObservedEvent};
use flowguard::graph::{EdgeKind, Node, ProvenanceGraph};
use flowguard::policy::{DecisionKind, PolicyId};
use flowguard::scenarios::file::load_yaml_file;
use flowguard::scenarios::{ScenarioOutcome, ScenarioRunner};

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;

    match command.as_str() {
        "replay" => {
            let scenario_path = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }

            let scenario = load_yaml_file(&scenario_path).map_err(|err| err.to_string())?;
            let outcome = ScenarioRunner::new().run(&scenario);
            print_replay_outcome(&outcome);

            if outcome.enforcement.decision.kind == DecisionKind::Block {
                Ok(ExitCode::from(1))
            } else {
                Ok(ExitCode::SUCCESS)
            }
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: flowguard replay <scenario.yaml>".to_string()
}

fn print_replay_outcome(outcome: &ScenarioOutcome) {
    let decision = &outcome.enforcement.decision;

    match decision.violations.first() {
        Some(violation) => {
            println!(
                "{} {}",
                decision_kind_name(decision.kind),
                policy_name(violation.policy)
            );
            println!();
            println!("sink:");
            println!("  {}", format_observed_event(&violation.sink_event));

            if let Some(explanation) = outcome.explanations.first() {
                println!();
                println!("why:");
                for step in &explanation.path {
                    let Some(edge) = outcome.graph.edge(step.via_edge) else {
                        println!("  missing edge {:?}", step.via_edge);
                        continue;
                    };
                    println!(
                        "  {} --{}--> {}",
                        format_node(&outcome.graph, edge.from),
                        edge_kind_name(edge.kind),
                        format_node(&outcome.graph, edge.to)
                    );
                }
            }
        }
        None => println!("{}", decision_kind_name(decision.kind)),
    }
}

fn format_observed_event(observed: &ObservedEvent) -> String {
    match &observed.event {
        Event::Send {
            process, fd, len, ..
        } => {
            format!(
                "SEND proc:{}@{} fd:{} len:{}",
                process.pid, process.start_time.0, fd.0, len
            )
        }
        Event::Exec {
            parent, program, ..
        } => {
            format!(
                "EXEC proc:{}@{} program:{}",
                parent.pid,
                parent.start_time.0,
                program.display()
            )
        }
        Event::Write {
            process, fd, len, ..
        } => {
            format!(
                "WRITE proc:{}@{} fd:{} len:{}",
                process.pid, process.start_time.0, fd.0, len
            )
        }
        Event::Open {
            process, fd, path, ..
        } => {
            format!(
                "OPEN proc:{}@{} fd:{} path:{}",
                process.pid,
                process.start_time.0,
                fd.0,
                path.display()
            )
        }
        Event::SocketCreate {
            process,
            fd,
            family,
            socket_type,
            protocol,
            ..
        } => {
            format!(
                "SOCKET_CREATE proc:{}@{} fd:{} family:{family:?} type:{socket_type:?} protocol:{protocol:?}",
                process.pid, process.start_time.0, fd.0
            )
        }
        Event::SetSockOpt {
            process,
            fd,
            level,
            option,
            ..
        } => {
            format!(
                "SET_SOCK_OPT proc:{}@{} fd:{} level:{level:?} option:{option:?}",
                process.pid, process.start_time.0, fd.0
            )
        }
        Event::Splice {
            process,
            from_fd,
            to_fd,
            len,
            ..
        } => {
            format!(
                "SPLICE proc:{}@{} from_fd:{} to_fd:{} len:{}",
                process.pid, process.start_time.0, from_fd.0, to_fd.0, len
            )
        }
        other => format!("{other:?}"),
    }
}

fn format_node(graph: &ProvenanceGraph, node_id: flowguard::graph::NodeId) -> String {
    match graph.nodes.get(&node_id) {
        Some(Node::Process(process)) => format!("proc:{}@{}", process.pid, process.start_time.0),
        Some(Node::File { path }) => format!("file:{}", path.display()),
        Some(Node::Pipe { pipe }) => format!("pipe:{}", pipe.0),
        Some(Node::Socket { socket }) => format!("socket:{}", socket.0),
        Some(Node::Endpoint(endpoint)) => format!("endpoint:{}:{}", endpoint.host, endpoint.port),
        None => format!("node:{}", node_id.0),
    }
}

fn decision_kind_name(kind: DecisionKind) -> &'static str {
    match kind {
        DecisionKind::Allow => "ALLOW",
        DecisionKind::Alert => "ALERT",
        DecisionKind::RequireApproval => "REQUIRE_APPROVAL",
        DecisionKind::Block => "BLOCK",
    }
}

fn policy_name(policy: PolicyId) -> &'static str {
    match policy {
        PolicyId::ExternalToExec => "ExternalToExec",
        PolicyId::SecretToNetwork => "SecretToNetwork",
        PolicyId::PromptToShellWithoutApproval => "PromptToShellWithoutApproval",
        PolicyId::ExternalToExecutableWrite => "ExternalToExecutableWrite",
        PolicyId::PromptToContainerRuntimeSocket => "PromptToContainerRuntimeSocket",
        PolicyId::CopyFailAfAlgPattern => "CopyFailAfAlgPattern",
    }
}

fn edge_kind_name(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Read => "READ",
        EdgeKind::Write => "WRITE",
        EdgeKind::Recv => "RECV",
        EdgeKind::Send => "SEND",
        EdgeKind::Fork => "FORK",
        EdgeKind::Exec => "EXEC",
        EdgeKind::Connect => "CONNECT",
    }
}
