//! Narrow Stripe error projection. Never return arbitrary strings, URLs, headers,
//! request data, or response text. General network readers remain protected.
use serde_json::{json, Value};

#[derive(Clone)]
pub struct Candidate {
    pub session: String,
    pub owner_session: String,
    pub cdp_id: String,
    pub http_status: u16,
    pub request_id: Option<String>,
}

/// Only Stripe's HTTPS API and payment-related resources qualify. Query strings
/// (which can contain client secrets) are neither inspected nor retained.
pub fn candidate(params: &Value, session: Option<&str>) -> Option<Candidate> {
    let response = params.get("response")?;
    let url = url::Url::parse(response.get("url")?.as_str()?).ok()?;
    if url.scheme() != "https"
        || url.host_str() != Some("api.stripe.com")
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let mut path = url.path_segments()?;
    if path.next() != Some("v1")
        || !matches!(
            path.next(),
            Some("payment_intents" | "setup_intents" | "payment_methods")
        )
    {
        return None;
    }
    let status = response.get("status")?.as_f64()?;
    if !(400.0..600.0).contains(&status) || status.fract() != 0.0 {
        return None;
    }
    let request_id = response
        .get("headers")
        .and_then(Value::as_object)
        .and_then(|headers| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("request-id"))
        })
        .and_then(|(_, value)| identifier(value, &["req_"]));
    Some(Candidate {
        session: session?.to_owned(),
        owner_session: String::new(),
        cdp_id: params.get("requestId")?.as_str()?.to_owned(),
        http_status: status as u16,
        request_id,
    })
}

fn identifier(value: &Value, prefixes: &[&str]) -> Option<String> {
    let value = value.as_str()?;
    prefixes.iter().find_map(|prefix| {
        let suffix = value.strip_prefix(prefix)?;
        // Excludes _secret_ and every separator outside the documented ID form.
        (suffix.len() >= 8
            && suffix.len() <= 64
            && suffix.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| value.to_owned())
    })
}

fn fixed(value: Option<&Value>, allowed: &[&str]) -> Option<String> {
    let value = value?.as_str()?;
    // Return the fixed local string, not untrusted response text.
    allowed
        .iter()
        .find(|known| **known == value)
        .map(|known| (*known).to_owned())
}

/// Parse at most 256 KiB, selecting fixed error codes and nonsecret IDs only.
/// Unknown values are omitted rather than echoed or recursively searched.
pub fn project(candidate: &Candidate, body: Option<&str>) -> Value {
    let mut out = json!({"processor":"stripe", "http_status":candidate.http_status});
    if let Some(id) = &candidate.request_id {
        out["request_id"] = json!(id);
    }
    let Some(body) = body else {
        out["body_status"] = json!("unavailable");
        return out;
    };
    if body.len() > 262144 {
        out["body_status"] = json!("oversized");
        return out;
    }
    let Ok(body) = serde_json::from_str::<Value>(body) else {
        out["body_status"] = json!("non_json");
        return out;
    };
    out["body_status"] = json!("parsed");
    let error = body
        .get("error")
        .or_else(|| body.get("last_payment_error"))
        .or_else(|| body.get("last_setup_error"));
    if let Some(error) = error {
        for (field, key, allowed) in [
            (
                "error_type",
                "type",
                &[
                    "api_error",
                    "card_error",
                    "idempotency_error",
                    "invalid_request_error",
                    "authentication_error",
                    "rate_limit_error",
                    "validation_error",
                ][..],
            ),
            (
                "code",
                "code",
                &[
                    "card_declined",
                    "expired_card",
                    "incorrect_cvc",
                    "incorrect_number",
                    "incorrect_zip",
                    "invalid_cvc",
                    "invalid_expiry_month",
                    "invalid_expiry_year",
                    "invalid_number",
                    "processing_error",
                    "authentication_required",
                    "payment_intent_authentication_failure",
                    "payment_intent_payment_attempt_failed",
                    "payment_intent_unexpected_state",
                    "setup_intent_authentication_failure",
                    "setup_intent_setup_attempt_failed",
                    "setup_intent_unexpected_state",
                    "payment_method_unactivated",
                    "payment_method_not_available",
                    "payment_method_provider_decline",
                    "payment_method_provider_timeout",
                    "payment_method_unsupported_type",
                    "payment_method_currency_mismatch",
                    "payment_method_customer_decline",
                    "payment_method_invalid_parameter",
                    "payment_method_microdeposit_failed",
                    "parameter_invalid_empty",
                    "parameter_invalid_integer",
                    "parameter_invalid_string_blank",
                    "parameter_missing",
                    "parameter_unknown",
                    "resource_missing",
                    "testmode_charges_only",
                    "livemode_mismatch",
                    "rate_limit",
                    "api_key_expired",
                ][..],
            ),
            (
                "decline_code",
                "decline_code",
                &[
                    "authentication_required",
                    "approve_with_id",
                    "call_issuer",
                    "card_not_supported",
                    "card_velocity_exceeded",
                    "currency_not_supported",
                    "do_not_honor",
                    "do_not_try_again",
                    "duplicate_transaction",
                    "expired_card",
                    "fraudulent",
                    "generic_decline",
                    "incorrect_number",
                    "incorrect_cvc",
                    "incorrect_pin",
                    "incorrect_zip",
                    "insufficient_funds",
                    "invalid_account",
                    "invalid_amount",
                    "invalid_cvc",
                    "invalid_expiry_month",
                    "invalid_expiry_year",
                    "invalid_number",
                    "invalid_pin",
                    "issuer_not_available",
                    "lost_card",
                    "merchant_blacklist",
                    "new_account_information_available",
                    "no_action_taken",
                    "not_permitted",
                    "offline_pin_required",
                    "online_or_offline_pin_required",
                    "pickup_card",
                    "pin_try_exceeded",
                    "processing_error",
                    "reenter_transaction",
                    "restricted_card",
                    "revocation_of_all_authorizations",
                    "revocation_of_authorization",
                    "security_violation",
                    "service_not_allowed",
                    "stolen_card",
                    "stop_payment_order",
                    "testmode_decline",
                    "transaction_not_allowed",
                    "try_again_later",
                    "withdrawal_count_limit_exceeded",
                ][..],
            ),
        ] {
            if let Some(value) = fixed(error.get(key), allowed) {
                out[field] = json!(value);
            }
        }
        let intent = error
            .pointer("/payment_intent/id")
            .or_else(|| error.pointer("/setup_intent/id"));
        if let Some(id) = intent.and_then(|v| identifier(v, &["pi_", "seti_"])) {
            out["intent_id"] = json!(id);
        }
    }
    if out.get("intent_id").is_none() {
        if let Some(id) = body
            .get("id")
            .and_then(|v| identifier(v, &["pi_", "seti_"]))
        {
            out["intent_id"] = json!(id);
        }
    }
    out
}
