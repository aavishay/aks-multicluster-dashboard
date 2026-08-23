//! Redaction of secrets and personal data before anything is sent to Claude.
//!
//! Pod logs are the highest-risk data this app can touch: they routinely carry
//! bearer tokens, connection strings, API keys and — on an identity-verification
//! platform — personal data belonging to end users who never consented to it
//! leaving the cluster. Everything on the diagnosis path passes through here
//! first.
//!
//! This is deliberately aggressive rather than clever. Over-redacting costs a
//! little diagnostic signal; under-redacting leaks a credential. Where the two
//! conflict, this over-redacts.
//!
//! It is emphatically not a guarantee — pattern matching cannot recognise every
//! secret, and a log line can carry sensitive data in a shape no rule
//! anticipates. It reduces exposure; it does not eliminate it. That's why the
//! UI shows the exact redacted payload before it is sent.

use regex::Regex;
use std::sync::OnceLock;

/// What a redacted span is replaced with. Kept distinctive so it is obvious in
/// the payload preview that redaction ran.
const MASK: &str = "[REDACTED]";

struct Rule {
    /// What this rule catches, surfaced in the redaction summary so the reader
    /// can tell *why* something disappeared.
    label: &'static str,
    pattern: Regex,
    /// When set, only this capture group is masked, preserving the surrounding
    /// context (e.g. keep `password=` visible, mask only the value).
    value_group: Option<usize>,
}

fn rules() -> &'static Vec<Rule> {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let r = |label: &'static str, pattern: &str, value_group: Option<usize>| Rule {
            label,
            // These patterns are compile-time constants in this file; a failure
            // here is a programming error, not a runtime condition.
            pattern: Regex::new(pattern).expect("redaction pattern must compile"),
            value_group,
        };
        vec![
            // JWTs — three base64url segments. Very common in request logs and
            // unambiguously a credential.
            r("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", None),
            // Provider key formats with distinctive prefixes.
            r("Anthropic key", r"sk-ant-[A-Za-z0-9_-]{16,}", None),
            r("OpenAI-style key", r"sk-[A-Za-z0-9]{20,}", None),
            r("GitHub token", r"gh[pousr]_[A-Za-z0-9]{16,}", None),
            r("AWS access key", r"AKIA[0-9A-Z]{16}", None),
            r("Google API key", r"AIza[0-9A-Za-z_-]{35}", None),
            r("Slack token", r"xox[baprs]-[A-Za-z0-9-]{10,}", None),
            // Azure AD client secrets and SAS tokens.
            r("Azure SAS token", r"(?i)\bsig=[A-Za-z0-9%+/=]{20,}", None),
            // `Authorization: Bearer <token>` — keep the header name.
            r("Bearer token", r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{16,})", Some(2)),
            r("Basic auth header", r"(?i)(basic\s+)([A-Za-z0-9+/=]{12,})", Some(2)),
            // Credentials embedded in a URL: scheme://user:secret@host
            r("URL credentials", r"([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:)([^\s@\[][^\s@]*)(@)", Some(2)),
            // key=value / key: value assignments for secret-ish names. Covers
            // JSON ("password": "x"), env dumps (PASSWORD=x) and logfmt.
            // The key name allows surrounding word characters so `DB_PASSWORD`
            // matches — `\b` alone fails there, since `_` is a word character
            // and there is no boundary between `DB_` and `PASSWORD`.
            //
            // The value must not *start* with `[`, so an already-inserted
            // `[REDACTED]` can't be re-matched into `[REDACTED]]`. Rust's regex
            // engine has no lookaround, so this is expressed in the charset.
            r(
                "secret assignment",
                r#"(?i)([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|client_secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|private[_-]?key|connection[_-]?string)[A-Za-z0-9_.-]*)(["']?\s*[:=]\s*["']?)([^\s,;"'}\[\]][^\s,;"'}\]]{3,})"#,
                Some(3),
            ),
            // PEM blocks — mask the body, keep the banner so its presence shows.
            r(
                "private key block",
                r"(?s)(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.*?)(-----END [A-Z ]*PRIVATE KEY-----)",
                Some(2),
            ),
            // Personal data. This app is used against identity-verification
            // workloads, so end-user PII in logs is a realistic hazard and not
            // ours to forward.
            r("email address", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", None),
            // Long digit runs: card numbers, national IDs, phone numbers. Bare
            // digits this long are almost never useful for diagnosis.
            r("long digit sequence", r"\b\d[\d -]{11,22}\d\b", None),
        ]
    })
}

/// Result of redacting one document.
#[derive(Debug, Clone, PartialEq)]
pub struct Redacted {
    pub text: String,
    /// Rule labels that fired, with counts — shown in the UI so the reader
    /// knows what was removed rather than silently receiving altered text.
    pub findings: Vec<(String, usize)>,
}

impl Redacted {
    /// Combines the findings from several redaction passes into one, so a
    /// payload assembled from multiple documents (status, events, manifest,
    /// logs) can report a single summary covering all of them.
    ///
    /// The returned `Redacted` exists only to call `.summary()` on — its
    /// `text` is always empty, since merging redacted text from unrelated
    /// documents into one string wouldn't mean anything. Use each part's own
    /// `text` for the actual output; use the merged value only for the
    /// combined summary.
    pub fn merge<'a>(parts: impl IntoIterator<Item = &'a Redacted>) -> Redacted {
        let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for part in parts {
            for (label, count) in &part.findings {
                *counts.entry(label.as_str()).or_insert(0) += count;
            }
        }
        Redacted {
            text: String::new(),
            findings: counts.into_iter().map(|(label, count)| (label.to_string(), count)).collect(),
        }
    }

    /// Human-readable one-liner for the payload preview.
    pub fn summary(&self) -> String {
        if self.findings.is_empty() {
            return "No secrets or personal data matched.".to_string();
        }
        let parts: Vec<String> = self
            .findings
            .iter()
            .map(|(label, count)| format!("{count}× {label}"))
            .collect();
        format!("Redacted: {}", parts.join(", "))
    }
}

/// Masks secrets and personal data in `input`.
pub fn redact(input: &str) -> Redacted {
    let mut text = input.to_string();
    let mut findings: Vec<(String, usize)> = Vec::new();

    for rule in rules() {
        let count = rule.pattern.find_iter(&text).count();
        if count == 0 {
            continue;
        }
        text = match rule.value_group {
            // Rebuild the match with only the value group masked, so
            // surrounding context stays readable.
            Some(group) => rule
                .pattern
                .replace_all(&text, |caps: &regex::Captures| {
                    let mut out = String::new();
                    for i in 1..caps.len() {
                        match caps.get(i) {
                            Some(m) if i == group => {
                                let _ = m;
                                out.push_str(MASK);
                            }
                            Some(m) => out.push_str(m.as_str()),
                            None => {}
                        }
                    }
                    out
                })
                .into_owned(),
            None => rule.pattern.replace_all(&text, MASK).into_owned(),
        };
        findings.push((rule.label.to_string(), count));
    }

    Redacted { text, findings }
}

/// Trims a document to a line budget, keeping the *end* — for logs the most
/// recent lines are the diagnostic ones. Returns the text plus a note when
/// anything was dropped.
///
/// Never truncates silently: an explanation built on a quietly shortened log is
/// worse than one the reader knows is partial.
pub fn tail_lines(input: &str, max_lines: usize) -> (String, Option<String>) {
    let lines: Vec<&str> = input.lines().collect();
    if lines.len() <= max_lines {
        return (input.to_string(), None);
    }
    let kept = &lines[lines.len() - max_lines..];
    (
        kept.join("\n"),
        Some(format!(
            "showing the last {max_lines} of {} lines",
            lines.len()
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redacted_text(input: &str) -> String {
        redact(input).text
    }

    /// The point of the module: a credential must not survive into the output.
    fn assert_scrubbed(input: &str, secret: &str) {
        let out = redacted_text(input);
        assert!(
            !out.contains(secret),
            "secret survived redaction!\n  input:  {input}\n  output: {out}\n  secret: {secret}"
        );
        assert!(out.contains(MASK), "expected a mask in output, got: {out}");
    }

    #[test]
    fn scrubs_jwts() {
        assert_scrubbed(
            "auth failed for eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "eyJhbGciOiJIUzI1NiJ9",
        );
    }

    #[test]
    fn scrubs_provider_key_formats() {
        assert_scrubbed("key=sk-ant-api03-abcdefghijklmnopqrstuvwx", "sk-ant-api03-abcdefghijklmnopqrstuvwx");
        assert_scrubbed("ghp_abcdefghijklmnopqrstuvwxyz01", "ghp_abcdefghijklmnopqrstuvwxyz01");
        assert_scrubbed("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE");
        assert_scrubbed("AIzaSyA1234567890abcdefghijklmnopqrstuv", "AIzaSyA1234567890abcdefghijklmnopqrstuv");
        assert_scrubbed("xoxb-123456789012-abcdefghijkl", "xoxb-123456789012-abcdefghijkl");
    }

    #[test]
    fn scrubs_bearer_tokens_but_keeps_the_header_name() {
        let out = redacted_text("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456");
        assert!(!out.contains("abcdefghijklmnopqrstuvwxyz123456"), "{out}");
        // The header name is diagnostic — an auth failure looks different from
        // a missing header — so it must survive.
        assert!(out.contains("Bearer"), "{out}");
        assert!(out.contains("Authorization"), "{out}");
    }

    #[test]
    fn scrubs_credentials_embedded_in_urls_but_keeps_the_host() {
        let out = redacted_text("dial postgres://appuser:sup3rs3cret@db.internal:5432/orders");
        assert!(!out.contains("sup3rs3cret"), "{out}");
        // Host and user are what make the line diagnostically useful.
        assert!(out.contains("db.internal:5432"), "{out}");
        assert!(out.contains("appuser"), "{out}");
    }

    #[test]
    fn scrubs_secret_assignments_across_common_encodings() {
        for (line, secret) in [
            (r#"{"password": "hunter2xyz"}"#, "hunter2xyz"),
            ("DB_PASSWORD=hunter2xyz", "hunter2xyz"),
            ("client_secret: hunter2xyz", "hunter2xyz"),
            ("api_key=hunter2xyz", "hunter2xyz"),
            ("access-token = hunter2xyz", "hunter2xyz"),
        ] {
            assert_scrubbed(line, secret);
        }
    }

    #[test]
    fn keeps_the_key_name_when_masking_its_value() {
        // Knowing *which* setting was wrong is often the whole diagnosis.
        let out = redacted_text("DB_PASSWORD=hunter2xyz");
        assert!(out.contains("DB_PASSWORD"), "{out}");
    }

    #[test]
    fn scrubs_pem_bodies_but_keeps_the_banner() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretkeymaterial\n-----END RSA PRIVATE KEY-----";
        let out = redacted_text(pem);
        assert!(!out.contains("MIIEowIBAAKCAQEAsecretkeymaterial"), "{out}");
        // Presence of a key in the logs is itself worth knowing.
        assert!(out.contains("BEGIN RSA PRIVATE KEY"), "{out}");
    }

    #[test]
    fn scrubs_personal_data() {
        assert_scrubbed("verification failed for jane.doe@example.com", "jane.doe@example.com");
        assert_scrubbed("card 4111 1111 1111 1111 declined", "4111 1111 1111 1111");
        assert_scrubbed("id 123456789012345", "123456789012345");
    }

    /// Redaction must not destroy the parts of a log line that carry the
    /// diagnosis, or the feature is useless.
    #[test]
    fn leaves_ordinary_diagnostic_text_intact() {
        let line = "E0822 10:01:23 controller.go:214] Failed to pull image \"myregistry.azurecr.io/inx-service:ffbe3449\": \
                    rpc error: code = NotFound desc = manifest unknown";
        let out = redacted_text(line);
        assert_eq!(out, line, "diagnostic text must survive untouched");
        assert!(redact(line).findings.is_empty());
    }

    #[test]
    fn timestamps_and_short_numbers_are_not_mistaken_for_pii() {
        for benign in [
            "2026-08-22T10:01:23Z restarting",
            "listening on port 8080",
            "replicas 3/5 ready",
            "exit code 137 (OOMKilled)",
            "took 1234 ms",
        ] {
            assert_eq!(redacted_text(benign), benign, "false positive on: {benign}");
        }
    }

    #[test]
    fn summary_names_what_fired_and_how_often() {
        let r = redact("a@b.com and c@d.com and password=supersecret");
        assert_eq!(r.findings.len(), 2, "{:?}", r.findings);
        let s = r.summary();
        assert!(s.contains("2× email address"), "{s}");
        assert!(s.contains("1× secret assignment"), "{s}");

        assert_eq!(redact("nothing sensitive here").summary(), "No secrets or personal data matched.");
    }

    /// This is the path `build_diagnosis_payload` relies on: findings from
    /// several documents (status/events/manifest/logs) collapse into one
    /// summary, with matching labels summed rather than listed separately.
    #[test]
    fn merge_sums_matching_labels_across_parts_and_keeps_others_distinct() {
        let status = redact("a@b.com");
        let events = redact("no findings here");
        let manifest = redact("c@d.com and password=supersecret");
        let logs = redact("password=anothersecret");

        let merged = Redacted::merge([&status, &events, &manifest, &logs]);
        assert_eq!(
            merged.findings,
            vec![("email address".to_string(), 2), ("secret assignment".to_string(), 2)]
        );
        assert_eq!(merged.summary(), "Redacted: 2× email address, 2× secret assignment");
    }

    #[test]
    fn merge_of_all_clean_parts_falls_back_to_the_no_findings_message() {
        let clean = redact("nothing sensitive here");
        let merged = Redacted::merge([&clean, &clean]);
        assert_eq!(merged.summary(), "No secrets or personal data matched.");
    }

    #[test]
    fn tail_lines_keeps_the_end_and_discloses_the_trim() {
        let text = (1..=100).map(|i| format!("line {i}")).collect::<Vec<_>>().join("\n");
        let (kept, note) = tail_lines(&text, 10);
        assert!(kept.starts_with("line 91"), "{kept}");
        assert!(kept.ends_with("line 100"));
        assert_eq!(kept.lines().count(), 10);
        // Silence here would let Claude reason over a partial log without
        // anyone knowing.
        assert_eq!(note.as_deref(), Some("showing the last 10 of 100 lines"));
    }

    #[test]
    fn tail_lines_leaves_short_input_alone() {
        let (kept, note) = tail_lines("a\nb\nc", 10);
        assert_eq!(kept, "a\nb\nc");
        assert_eq!(note, None);
    }

    /// Redacting already-redacted text must not corrupt the mask — an earlier
    /// version produced `[REDACTED]]` because the value charset excluded `]`
    /// but not `[`, so it re-matched `[REDACTED` and appended a bracket.
    ///
    /// Text stability is the guarantee; a rule whose value pattern legitimately
    /// spans a mask (the PEM body is `.*?`) may still re-report on a second
    /// pass, which is cosmetic.
    #[test]
    fn redaction_is_stable_over_already_redacted_text() {
        for input in [
            "password=hunter2xyz and a@b.com",
            "DB_PASSWORD=hunter2xyz",
            "postgres://appuser:sup3rs3cret@db.internal:5432/orders",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
        ] {
            let once = redact(input);
            let twice = redact(&once.text);
            assert_eq!(twice.text, once.text, "not stable for: {input}");
            assert!(!once.text.contains("]]"), "doubled bracket for {input}: {}", once.text);
        }
    }
}
