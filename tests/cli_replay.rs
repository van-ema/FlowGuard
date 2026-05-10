use std::process::{Command, Output};

fn flowguard_replay(path: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_flowguard"))
        .arg("replay")
        .arg(path)
        .output()
        .expect("failed to run flowguard replay")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout was not utf-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr was not utf-8")
}

#[test]
fn replay_secret_exfil_blocks_with_explanation() {
    let output = flowguard_replay("scenarios/secret_exfil.yaml");
    let stdout = stdout(&output);

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(stdout.contains("BLOCK SecretToNetwork"));
    assert!(stdout.contains("sink:"));
    assert!(stdout.contains("SEND proc:301@2010 fd:6 len:256"));
    assert!(stdout.contains("why:"));
    assert!(stdout.contains("file:/home/user/.ssh/id_rsa --READ--> proc:300@2000"));
    assert!(stdout.contains("proc:301@2010 --SEND--> endpoint:evil.example:443"));
}

#[test]
fn replay_copy_fail_blocks_af_alg_socket() {
    let output = flowguard_replay("scenarios/copy_fail.yaml");
    let stdout = stdout(&output);

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(stdout.contains("BLOCK CopyFailAfAlgPattern"));
    assert!(stdout.contains("sink:"));
    assert!(
        stdout.contains(
            "SOCKET_CREATE proc:400@3000 fd:3 family:AfAlg type:SeqPacket protocol:Default"
        )
    );
}

#[test]
fn replay_prompt_shell_blocks_without_approval() {
    let output = flowguard_replay("scenarios/prompt_shell_block.yaml");
    let stdout = stdout(&output);

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(stdout.contains("BLOCK PromptToShellWithoutApproval"));
    assert!(stdout.contains("sink:"));
    assert!(stdout.contains("EXEC proc:700@6000 program:/bin/bash"));
    assert!(stdout.contains("why:"));
    assert!(stdout.contains("proc:700@6000 --EXEC--> proc:701@6010"));
}

#[test]
fn replay_benign_send_allows() {
    let output = flowguard_replay("scenarios/benign_send.yaml");

    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "ALLOW\n");
}

#[test]
fn replay_prompt_shell_approved_allows() {
    let output = flowguard_replay("scenarios/prompt_shell_approved.yaml");

    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "ALLOW\n");
}

#[test]
fn replay_benign_socket_allows() {
    let output = flowguard_replay("scenarios/benign_socket.yaml");

    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "ALLOW\n");
}
