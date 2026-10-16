use crate::connection::Response;
use crate::flags::Flags;
use crate::native::actions::{execute_command, DaemonState};
use crate::native::policy::{ActionPolicy, ConfirmActions};
use serde_json::Value;

pub enum Execution {
    SessionRequired,
    Complete(Response),
}

pub fn is_local_action(action: &str) -> bool {
    matches!(
        action,
        "auth_save"
            | "auth_list"
            | "auth_show"
            | "auth_delete"
            | "credentials_set"
            | "credentials_get"
            | "credentials_delete"
            | "credentials_list"
    )
}

/// Vault operations use the same native dispatcher and policy checks without
/// creating a browser session. A pending confirmation has executed no effect;
/// its continuation requires the normal session-owned confirmation protocol.
pub fn execute(cmd: &Value, flags: &Flags) -> Result<Execution, String> {
    if !cmd
        .get("action")
        .and_then(Value::as_str)
        .is_some_and(is_local_action)
    {
        return Ok(Execution::SessionRequired);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("local_vault_runtime: {e}"))?;
    runtime.block_on(async {
        let mut state = DaemonState::new();
        state.session_id = flags.session.clone();
        if let Some(path) = flags.action_policy.as_deref() {
            state.policy = Some(ActionPolicy::load(path)?);
        }
        if let Some(categories) = flags.confirm_actions.as_deref() {
            state.confirm_actions = Some(ConfirmActions {
                categories: categories
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect(),
            });
        }
        let response = execute_command(cmd, &mut state).await;
        if state.pending_confirmation.is_some() {
            return Ok(Execution::SessionRequired);
        }
        let response =
            serde_json::from_value(response).map_err(|e| format!("local_vault_response: {e}"))?;
        Ok(Execution::Complete(response))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn local_vault_excludes_every_browser_credential_effect() {
        for action in [
            "auth_login",
            "auth_fill",
            "auth_export",
            "credentials",
            "launch",
            "close",
            "session_info",
            "unknown",
        ] {
            assert!(!is_local_action(action), "{action}");
        }
        for action in [
            "auth_save",
            "auth_list",
            "auth_show",
            "auth_delete",
            "credentials_set",
            "credentials_get",
            "credentials_delete",
            "credentials_list",
        ] {
            assert!(is_local_action(action), "{action}");
        }
    }

    #[test]
    fn local_vault_invalid_input_returns_native_error_without_session() {
        let flags = crate::flags::parse_flags(&[]);
        let result = execute(
            &json!({"id":"fixture", "action":"auth_show", "name":"../invalid"}),
            &flags,
        )
        .unwrap();
        let Execution::Complete(response) = result else {
            panic!("must not create a session")
        };
        assert!(!response.success);
        assert!(response.error.unwrap().contains("Invalid"));
    }

    #[test]
    fn local_vault_confirmation_retains_session_protocol_before_effect() {
        let mut flags = crate::flags::parse_flags(&[]);
        flags.confirm_actions = Some("auth_save".into());
        let result = execute(
            &json!({"id":"fixture", "action":"auth_save", "name":"../invalid"}),
            &flags,
        )
        .unwrap();
        assert!(matches!(result, Execution::SessionRequired));
    }

    #[test]
    fn local_vault_missing_policy_is_an_error() {
        let mut flags = crate::flags::parse_flags(&[]);
        flags.action_policy = Some("/missing-local-vault-policy-7a5".into());
        assert!(execute(&json!({"action":"auth_list"}), &flags).is_err());
    }
}
