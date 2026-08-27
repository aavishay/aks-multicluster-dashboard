//! Shared transient-network-error classification and retry backoff. Used by
//! `commands::with_retry` (retrying a whole Tauri command) and
//! `k8s::list_pods_page` (retrying a single page within a larger paginated
//! fetch) — different callers, same underlying "is this worth trying again"
//! judgment call, so it lives in its own leaf module rather than either of
//! those two depending on the other.

use std::future::Future;
use std::time::Duration;

/// Extra attempts `retry_transient` allows beyond the first, for a failure
/// that looks transient. Kept small — this is papering over a momentary
/// network blip (a VPN hiccup, a dropped TCP connection), not standing in
/// for a cluster that's genuinely unreachable, which should still surface
/// promptly rather than making the user wait through several multiplied
/// timeouts.
const MAX_RETRIES: u32 = 2;
const RETRY_DELAY: Duration = Duration::from_millis(500);

/// Substrings of the lower-cased error text that mark a failure as a
/// transport-level blip worth retrying, rather than something retrying
/// won't fix (auth failure, RBAC denial, a resource that doesn't exist, or
/// a deadline timeout — re-issuing a request right after a full operation
/// timeout would just make a genuinely slow/unreachable cluster take
/// several times as long to report that, for no benefit). Matched against
/// the fully-formatted error string rather than a structured error type,
/// since every call site already collapses its `kube::Error` into a
/// `String` before it reaches here — a pragmatic tradeoff, not a precise
/// classification.
const TRANSIENT_ERROR_MARKERS: &[&str] = &[
    "connection reset",
    "connection refused",
    "connection closed",
    "broken pipe",
    "unexpected eof",
    "eof while parsing",
    "end of file before message length reached",
    "error trying to connect",
    "dns error",
    "failed to lookup address",
    "temporary failure in name resolution",
    "tls handshake",
    "reading a body from connection", // the connection died mid-transfer, after headers but before the body finished
    "os error 54", // ECONNRESET
    "os error 32", // EPIPE
];

fn is_transient_error(message: &str) -> bool {
    if message.starts_with("Timed out after") {
        return false;
    }
    let lower = message.to_lowercase();
    TRANSIENT_ERROR_MARKERS.iter().any(|marker| lower.contains(marker))
}

/// Retries `operation` up to `MAX_RETRIES` additional times if it fails with
/// what looks like a transient network error, waiting `RETRY_DELAY` between
/// attempts. Generic over the operation so it can wrap anything from a whole
/// Tauri command to a single page within a larger paginated fetch — callers
/// decide what "one attempt" means; this only decides whether a failed
/// attempt is worth repeating.
pub async fn retry_transient<T, F, Fut>(mut operation: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let mut attempt = 0;
    loop {
        attempt += 1;
        match operation().await {
            Ok(value) => return Ok(value),
            Err(e) if attempt <= MAX_RETRIES && is_transient_error(&e) => {
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_transient_error_matches_common_network_blips() {
        assert!(is_transient_error("Failed to list pods: error trying to connect: dns error: failed to lookup address information"));
        assert!(is_transient_error("Failed to get node 'x': connection reset by peer (os error 54)"));
        assert!(is_transient_error("Failed to list events: IO error: broken pipe"));
        assert!(is_transient_error("SOME WRAPPER: Connection Refused"));
        // Reproduced live against a real cluster: the connection died mid-body-
        // transfer on a full-page pods list, after headers but before the body
        // finished — a real (if unusually-worded) transient blip, not one of
        // the other markers above.
        assert!(is_transient_error("Failed to list pods: ServiceError: error reading a body from connection"));
    }

    #[test]
    fn is_transient_error_rejects_the_deadline_timeout_message() {
        assert!(!is_transient_error(
            "Timed out after 60s talking to 'aks-dev-weu-ng'. If this is a private cluster, check that you're connected to the VPN."
        ));
    }

    #[test]
    fn is_transient_error_rejects_non_network_failures() {
        assert!(!is_transient_error("Failed to get pod 'x': pods \"x\" not found"));
        assert!(!is_transient_error("Failed to list nodes: Unauthorized"));
        assert!(!is_transient_error("Unsupported workload kind 'CronJob'"));
    }

    #[tokio::test]
    async fn retry_transient_recovers_from_a_transient_failure() {
        let attempts = std::cell::Cell::new(0);
        let result = retry_transient(|| {
            attempts.set(attempts.get() + 1);
            let this_attempt = attempts.get();
            async move {
                if this_attempt < 2 {
                    Err("connection reset by peer (os error 54)".to_string())
                } else {
                    Ok(42)
                }
            }
        })
        .await;
        assert_eq!(result, Ok(42));
        assert_eq!(attempts.get(), 2, "should have recovered on the second attempt");
    }

    #[tokio::test]
    async fn retry_transient_does_not_retry_a_non_transient_error() {
        let attempts = std::cell::Cell::new(0);
        let result = retry_transient(|| {
            attempts.set(attempts.get() + 1);
            async move { Err::<(), _>("pods \"x\" not found".to_string()) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.get(), 1, "a non-transient error should not be retried at all");
    }

    #[tokio::test]
    async fn retry_transient_gives_up_after_max_retries() {
        let attempts = std::cell::Cell::new(0);
        let result = retry_transient(|| {
            attempts.set(attempts.get() + 1);
            async move { Err::<(), _>("connection reset by peer (os error 54)".to_string()) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.get(), 1 + MAX_RETRIES, "should attempt exactly 1 + MAX_RETRIES times before giving up, never fewer or more");
    }
}
