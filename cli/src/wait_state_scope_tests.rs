use super::*;
use crate::commands::parse_command;
use crate::test_utils::EnvGuard;

fn argv(s: &str) -> Vec<String> {
    s.split_whitespace().map(String::from).collect()
}

#[test]
fn wait_states_are_command_local() {
    let guard = EnvGuard::new(&["AGENT_BROWSER_STATE"]);
    guard.remove("AGENT_BROWSER_STATE");
    for state in ["attached", "detached", "hidden", "visible"] {
        let raw = argv(&format!(
            "wait #user_email_login --state {state} --timeout 20000"
        ));
        let flags = parse_flags(&raw);
        assert!(!flags.cli_state);
        let command = parse_command(&clean_args(&raw), &flags).unwrap();
        assert_eq!(command["state"], state);
        assert_eq!(command["selector"], "#user_email_login");
        assert_eq!(command["timeout"], 20000);
    }
}

#[test]
fn wait_invalid_states_fail_before_dispatch() {
    for raw in [
        "wait #x --state",
        "wait #x --state nonsense",
        "wait #x --state attached --state hidden",
        "wait 100 --state detached",
        "wait --url example --state detached",
    ] {
        let raw = argv(raw);
        let flags = parse_flags(&raw);
        assert!(parse_command(&clean_args(&raw), &flags).is_err());
    }
}

#[test]
fn saved_state_and_element_state_are_distinct() {
    for raw in [
        "--state auth.json wait #x --state attached",
        "wait #x --storage-state auth.json --state attached",
        "--storage-state auth.json wait #x --state attached",
    ] {
        let raw = argv(raw);
        let flags = parse_flags(&raw);
        assert_eq!(flags.state.as_deref(), Some("auth.json"));
        assert!(flags.cli_state);
        let command = parse_command(&clean_args(&raw), &flags).unwrap();
        assert_eq!(command["state"], "attached");
    }
}

#[test]
fn other_commands_keep_global_saved_state() {
    let raw = argv("open https://example.test --state auth.json");
    let flags = parse_flags(&raw);
    assert_eq!(flags.state.as_deref(), Some("auth.json"));
    assert_eq!(clean_args(&raw), argv("open https://example.test"));
}
