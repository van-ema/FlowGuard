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
fn replay_external_executable_write_blocks_with_explanation() {
    let output = flowguard_replay("scenarios/external_executable_write.yaml");
    let stdout = stdout(&output);

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(stdout.contains("BLOCK ExternalToExecutableWrite"));
    assert!(stdout.contains("sink:"));
    assert!(stdout.contains("WRITE proc:720@6200 fd:4 len:512"));
    assert!(stdout.contains("why:"));
    assert!(stdout.contains("endpoint:downloads.evil.example:443 --RECV--> proc:720@6200"));
    assert!(stdout.contains("proc:720@6200 --WRITE--> file:/usr/local/bin/agent-helper"));
}

#[test]
fn replay_sandbox_escape_docker_socket_blocks() {
    let output = flowguard_replay("scenarios/sandbox_escape_docker_socket.yaml");
    let stdout = stdout(&output);

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(stdout.contains("BLOCK PromptToContainerRuntimeSocket"));
    assert!(stdout.contains("sink:"));
    assert!(stdout.contains("OPEN proc:740@6400 fd:3 path:/var/run/docker.sock"));
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
fn replay_benign_external_download_allows() {
    let output = flowguard_replay("scenarios/benign_external_download.yaml");

    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "ALLOW\n");
}

#[test]
fn replay_benign_tmp_socket_file_allows() {
    let output = flowguard_replay("scenarios/benign_tmp_socket_file.yaml");

    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "ALLOW\n");
}

#[test]
fn replay_malformed_missing_fd_warns_and_continues() {
    let output = flowguard_replay("scenarios/malformed_missing_fd.yaml");
    let stderr = stderr(&output);

    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(stdout(&output), "ALLOW\n");
    assert!(stderr.contains("warning: sequence:1 kind:MissingFd"));
    assert!(stderr.contains("missing fd mapping"));
}

#[test]
fn replay_benign_socket_allows() {
    let output = flowguard_replay("scenarios/benign_socket.yaml");

    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "ALLOW\n");
}
