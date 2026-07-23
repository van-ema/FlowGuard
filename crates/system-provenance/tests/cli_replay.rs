use std::path::PathBuf;
use std::process::{Command, Output};

fn flowguard_replay_args(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_flowguard"))
        .args(args)
        .output()
        .expect("failed to run flowguard")
}

fn flowguard_replay(path: &str) -> Output {
    let scenario_path = scenario_path(path);
    flowguard_replay_args(&["replay", scenario_path.to_str().unwrap()])
}

fn scenario_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
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
fn replay_secret_exfil_json_includes_observability_report() {
    let scenario_path = scenario_path("scenarios/secret_exfil.yaml");
    let output = flowguard_replay_args(&["replay", scenario_path.to_str().unwrap(), "--json"]);
    let stdout = stdout(&output);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("invalid json report");

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert_eq!(stderr(&output), "");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["scenario"], "secret_exfil");
    assert_eq!(report["decision"]["kind"], "Block");
    assert_eq!(report["violations"][0]["policy"], "SecretToNetwork");
    assert_eq!(report["event_records"].as_array().unwrap().len(), 10);
    assert_eq!(report["warnings"].as_array().unwrap().len(), 0);
    assert!(!report["graph"]["nodes"].as_array().unwrap().is_empty());
    assert!(!report["graph"]["edges"].as_array().unwrap().is_empty());
    assert!(!report["node_labels"].as_array().unwrap().is_empty());
    assert_eq!(report["explanations"][0]["policy"], "SecretToNetwork");

    let send_record = report["event_records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["kind"] == "Send")
        .expect("missing send record");
    assert_eq!(send_record["sequence"], 9);
    assert!(send_record["edge_id"].as_u64().is_some());
    assert_eq!(send_record["violation_indices"][0], 0);
}

#[test]
fn demo_secret_exfil_json_blocks_with_observability_report() {
    let output = flowguard_replay_args(&["demo", "secret-exfil", "--json"]);
    let stdout = stdout(&output);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("invalid json report");

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert_eq!(stderr(&output), "");
    assert_eq!(report["scenario"], "demo_secret_exfil");
    assert_eq!(report["decision"]["kind"], "Block");
    assert_eq!(report["violations"][0]["policy"], "SecretToNetwork");
    assert_eq!(report["event_records"].as_array().unwrap().len(), 10);
    assert_eq!(report["warnings"].as_array().unwrap().len(), 0);
    assert_eq!(report["explanations"][0]["policy"], "SecretToNetwork");

    let first_step = &report["explanations"][0]["path"][0];
    assert_eq!(first_step["edge_kind"], "Read");
    assert_eq!(first_step["from_display"], "file:/home/user/.ssh/id_rsa");

    let send_record = report["event_records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["kind"] == "Send")
        .expect("missing send record");
    assert_eq!(send_record["violation_indices"][0], 0);
    assert!(
        send_record["event"]
            .as_str()
            .unwrap()
            .contains("SEND proc:801@7010 fd:6")
    );
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
fn replay_false_positive_secret_then_unrelated_send_blocks_by_process_taint() {
    let output = flowguard_replay("scenarios/false_positive_secret_then_unrelated_send.yaml");
    let stdout = stdout(&output);

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(stdout.contains("BLOCK SecretToNetwork"));
    assert!(stdout.contains("SEND proc:900@8000 fd:4 len:2"));
    assert!(stdout.contains("file:/home/user/.ssh/id_rsa --READ--> proc:900@8000"));
    assert!(stdout.contains("proc:900@8000 --SEND--> endpoint:telemetry.example:443"));
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

#[test]
fn observe_requires_command_separator() {
    let output = flowguard_replay_args(&["observe", "--json"]);
    let stderr = stderr(&output);

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr.contains("flowguard observe [--json] [--raw-strace <path>] -- <command...>"));
}

#[test]
fn observe_raw_strace_requires_path() {
    let output = flowguard_replay_args(&["observe", "--raw-strace"]);
    let stderr = stderr(&output);

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr.contains("flowguard observe [--json] [--raw-strace <path>] -- <command...>"));
}

#[test]
fn protect_requires_command_separator() {
    let output = flowguard_replay_args(&["protect", "--json"]);
    let stderr = stderr(&output);

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr.contains("flowguard protect [--json] -- <command...>"));
}
