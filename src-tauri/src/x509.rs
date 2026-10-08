//! Just enough of X.509 to say what a certificate is for and when it expires:
//! subject, issuer, alternative names, validity and whether it is a CA.
//!
//! Hand-rolled over DER rather than a parser crate: these few fields sit at
//! fixed places in a structure unchanged since RFC 5280, and everything here
//! is bounds-checked reading of bytes the cluster already holds — nothing is
//! verified, trusted or acted on, only shown.

use base64::Engine;
use chrono::{NaiveDate, TimeZone, Utc};

/// What the Overview shows of one certificate. Mirrors `CertificateInfo` in types.ts.
#[derive(serde::Serialize, Clone, Debug, PartialEq, Default)]
pub struct CertificateInfo {
    /// `CN=…, O=…`, in the certificate's own order.
    pub subject: String,
    pub issuer: String,
    /// DNS names and IP addresses it is valid for.
    pub sans: Vec<String>,
    /// RFC 3339 UTC.
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub is_ca: bool,
}

/// One DER element: its tag and contents.
struct Tlv<'a> {
    tag: u8,
    body: &'a [u8],
}

/// Reads the element at the start of `input`, returning it and what follows.
fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        // Long form: the low bits say how many length bytes follow.
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        (rest[..n].iter().fold(0usize, |acc, &b| (acc << 8) | b as usize), &rest[n..])
    };
    (rest.len() >= len).then(|| (Tlv { tag, body: &rest[..len] }, &rest[len..]))
}

/// Every element inside a constructed one.
fn children(mut body: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = Vec::new();
    while let Some((t, rest)) = read(body) {
        out.push(t);
        body = rest;
    }
    out
}

const SEQUENCE: u8 = 0x30;

/// Attribute types worth naming; anything else is left out of the string.
fn attribute_name(oid: &[u8]) -> Option<&'static str> {
    Some(match oid {
        [0x55, 0x04, 0x03] => "CN",
        [0x55, 0x04, 0x0a] => "O",
        [0x55, 0x04, 0x0b] => "OU",
        [0x55, 0x04, 0x06] => "C",
        [0x55, 0x04, 0x07] => "L",
        [0x55, 0x04, 0x08] => "ST",
        _ => return None,
    })
}

fn string_value(t: &Tlv) -> String {
    match t.tag {
        // BMPString: UTF-16BE.
        0x1e => String::from_utf16_lossy(&t.body.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect::<Vec<_>>()),
        _ => String::from_utf8_lossy(t.body).into_owned(),
    }
}

/// A distinguished name as `CN=…, O=…`.
fn name(t: &Tlv) -> String {
    children(t.body)
        .iter()
        .flat_map(|rdn| children(rdn.body))
        .filter_map(|atv| {
            let parts = children(atv.body);
            let (oid, value) = (parts.first()?, parts.get(1)?);
            Some(format!("{}={}", attribute_name(oid.body)?, string_value(value)))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// UTCTime (`YYMMDDHHMMSSZ`, 1950–2049) or GeneralizedTime (`YYYYMMDDHHMMSSZ`).
fn time(t: &Tlv) -> Option<String> {
    let s = std::str::from_utf8(t.body).ok()?.strip_suffix('Z')?;
    // Digits only before any slicing: a multi-byte character would put a
    // slice boundary inside it, and malformed bytes must not panic.
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, rest) = match t.tag {
        0x17 if s.len() == 12 => {
            let yy: i32 = s[..2].parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &s[2..])
        }
        0x18 if s.len() == 14 => (s[..4].parse().ok()?, &s[4..]),
        _ => return None,
    };
    let field = |i: usize| rest.get(i..i + 2)?.parse::<u32>().ok();
    let date = NaiveDate::from_ymd_opt(year, field(0)?, field(2)?)?.and_hms_opt(field(4)?, field(6)?, field(8)?)?;
    Some(Utc.from_utc_datetime(&date).to_rfc3339())
}

fn general_names(body: &[u8]) -> Vec<String> {
    let Some((seq, _)) = read(body) else { return Vec::new() };
    children(seq.body)
        .iter()
        .filter_map(|n| match n.tag {
            0x82 => Some(String::from_utf8_lossy(n.body).into_owned()),
            0x87 if n.body.len() == 4 => Some(n.body.iter().map(u8::to_string).collect::<Vec<_>>().join(".")),
            0x87 if n.body.len() == 16 => Some(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(n.body).ok()?).to_string()),
            _ => None,
        })
        .collect()
}

/// One DER certificate, or `None` if it is not one.
pub fn parse_der(der: &[u8]) -> Option<CertificateInfo> {
    let (cert, _) = read(der).filter(|(t, _)| t.tag == SEQUENCE)?;
    let tbs = children(cert.body).into_iter().next().filter(|t| t.tag == SEQUENCE)?;
    let mut fields = children(tbs.body).into_iter().peekable();
    // [0] version is optional: absent means v1.
    if fields.peek().is_some_and(|t| t.tag == 0xa0) {
        fields.next();
    }
    let _serial = fields.next()?;
    let _signature = fields.next()?;
    let issuer = fields.next()?;
    let validity = fields.next()?;
    let subject = fields.next()?;
    let _spki = fields.next()?;
    let times = children(validity.body);

    let mut info = CertificateInfo {
        subject: name(&subject),
        issuer: name(&issuer),
        not_before: times.first().and_then(time),
        not_after: times.get(1).and_then(time),
        ..Default::default()
    };
    // [3] extensions, after the optional issuer/subject unique IDs.
    if let Some(ext) = fields.find(|t| t.tag == 0xa3) {
        let list = read(ext.body).map(|(t, _)| children(t.body)).unwrap_or_default();
        for e in list {
            let parts = children(e.body);
            let (Some(oid), Some(value)) = (parts.first(), parts.last()) else { continue };
            match oid.body {
                // subjectAltName
                [0x55, 0x1d, 0x11] => info.sans = general_names(value.body),
                // basicConstraints: SEQUENCE { cA BOOLEAN DEFAULT FALSE, … }
                [0x55, 0x1d, 0x13] => {
                    info.is_ca = read(value.body)
                        .and_then(|(seq, _)| children(seq.body).into_iter().next())
                        .is_some_and(|b| b.tag == 0x01 && b.body.first().is_some_and(|&v| v != 0));
                }
                _ => {}
            }
        }
    }
    Some(info)
}

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

/// Every certificate in a PEM bundle, in order — the leaf first in a chain.
/// Anything else in the text, a private key included, is skipped unread.
pub fn parse_pem_bundle(text: &str) -> Vec<CertificateInfo> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let Some(end) = after.find(END) else { break };
        let b64: String = after[..end].chars().filter(|c| !c.is_whitespace()).collect();
        if let Some(info) = base64::engine::general_purpose::STANDARD.decode(b64).ok().and_then(|der| parse_der(&der)) {
            out.push(info);
        }
        rest = &after[end + END.len()..];
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Test certificates generated with openssl for these tests; the expected
    // values are openssl's own reading of them.
    pub(crate) const LEAF: &str = r"-----BEGIN CERTIFICATE-----
MIIDLjCCAhagAwIBAgIJAOisddlFB0mZMA0GCSqGSIb3DQEBCwUAMDoxCzAJBgNV
BAYTAklMMRMwEQYDVQQKDApGbGVldCBUZXN0MRYwFAYDVQQDDA1GbGVldCBUZXN0
IENBMB4XDTI2MTAwODE4NTAzOVoXDTI2MTAyODE4NTAzOVowLzETMBEGA1UECgwK
RmxlZXQgVGVzdDEYMBYGA1UEAwwPYXBpLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEArY/UhlxzPcxYmenndL8tcOpNNuFwhY32boYF
0f/F82VLY+CO58BBzJg2cIlqomsEDqBbBuDCW/cxg46kwRfc7qswN4zS0YbhH+kR
L/rI1qqUVXUqAMnWcKOtXgjDdlEOy6lOnLiWLywi6LMcIAnJRX/BnDZ85cp7mw1g
wQYFQG7Gr/kO0FyxhcA7kH/amnN/f/feGxTQ5uVK2DmBO1GQdgYS0xljePFcHNk4
lSlvIkOWnbS5cL7zz8lSKsSKdDHF8iD9ReY5WfMjCmOVkwophl/Rjd2tQa2O+f9H
bsrs0VuN8Ks2BSovUfPOA4ylpS8HuTIbXtI4z1Kj2YFl81aI8wIDAQABo0IwQDAz
BgNVHREELDAqgg9hcGkuZXhhbXBsZS5jb22CESouYXBpLmV4YW1wbGUuY29thwQK
AAAHMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBAK02kvWW0j0qtehFNm27
kgz3Qj1aFyX55w4rT5a2fl7DmFGOEmbzg2he4xsi0YxR8QcP2vejhJ4foXm1UM+N
p6UVd2667c+jU6RaakBaxJZGwoW75K7aeRj5MOpoR8iteoPkotoLzcBO5Jd2zYXt
dqHX5dcgB3ydU6xFzTo5SmKse5cFYmVBdBiBqMFFtgo/LoKN20TDrjWlMB3Hf7SI
P0G0TrKkzmWAWQMRkLlrP2GeMGbWfDpg93nABdaMlX9ZnT64LWAMOFuNZlv8Ccff
TOPCECZ6SwIEEAKG8Qwszwm7i02MJBI+kXcOtblnTPQHwl9SPe8Q7qbVkb5euY7q
h94=
-----END CERTIFICATE-----";
    pub(crate) const CA: &str = r"-----BEGIN CERTIFICATE-----
MIIDCjCCAfKgAwIBAgIJAMy1sUEmK1jQMA0GCSqGSIb3DQEBCwUAMDoxCzAJBgNV
BAYTAklMMRMwEQYDVQQKDApGbGVldCBUZXN0MRYwFAYDVQQDDA1GbGVldCBUZXN0
IENBMB4XDTI2MTAwODE4NTAzOVoXDTM2MTAwNTE4NTAzOVowOjELMAkGA1UEBhMC
SUwxEzARBgNVBAoMCkZsZWV0IFRlc3QxFjAUBgNVBAMMDUZsZWV0IFRlc3QgQ0Ew
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwtqKAvup2AoK0lX8Spqb0
JhnRFCzS9R86zogcqUn/kSK7BPRIqVAPz9OLHsJJDMkcM56GuH56LSX9+EYDLffZ
kMFxYhvK3n0mtsNLee1s2RM/6tV/GXkQt7u/2l2TVQPx/TOKSVMFtB4voqHgyy1Y
3nvYZbDw8tGXc8E5MfNYNG7Y+TO8gm6oRaKY2Pnw8htr++/k84r9inQWdo5dsWxJ
c02Q/TK0qgwgJ5BsK1uuezzgKYOj1FsQpVEHyJFfOf5K1OXkk3cLyeHmBzxHy54B
F5cuyIW8zNBMe49042R6wamUPpfcqXAP4DxJB+lUwDhYfiMuaoqaREnvvMiELuDF
AgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAKCT
pgEAj64FJoQwifgYWoSj+msI0V3iOvmjK5DqFpK0XL+ZPJQWIV1wQBLMsre8ZZc8
m4FuhfRg1g9hwrSJz3zVGJg9USlAiA0+ktO+LwTbevFX1Uu51eeQaLsxwDwWVpil
v7GFGTVRmrDvd1J4MfNBsGGAyn1/CAYs9o7c2pPBzdX/3JP3wh/iBeGfZHY46bab
QA2r493ps/HGZI0TmGA2fILM/N4rOedaF4w9VDGRcRpKs//qfNZWpJS7SYSx6oi8
YMYDCP5D6w1mRVN2ChnNzST+i/JZbyOaHJ1Q+as6cfUETHf1KBwsvIRLF1efMM+y
soo7g2Kl+2l8fDvSv7s=
-----END CERTIFICATE-----";
    pub(crate) const FAR: &str = r"-----BEGIN CERTIFICATE-----
MIICGjCCAcACCQDnsHYe80tfzDAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9mYXIu
ZXhhbXBsZS5jb20wIBcNMjYxMDA4MTg1MDUxWhgPMjA1NDAyMjMxODUwNTFaMBox
GDAWBgNVBAMMD2Zhci5leGFtcGxlLmNvbTCCAUswggEDBgcqhkjOPQIBMIH3AgEB
MCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP///////////////zBb
BCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6k+ez671V
dpiGvGUdBrDMU7D2O848PifSYEsDFQDEnTYIhucEk2pmeOETnSa3gZ9+kARBBGsX
0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivO
M1drMV7Oy7ZAaDe/UfUCIQD/////AAAAAP//////////vOb6racXnoTzucrC/GMl
UQIBAQNCAATwbW36EJaHjCWj/MBxARhgrzVfGuatfFByMY2gHgTLNt+nrrTmLHjQ
JSLvbXZwxSGzdHGpfgjylZSO7Wcis27EMAoGCCqGSM49BAMCA0gAMEUCIQD3tppa
MmZYWARGALjtjrqEOsssinAb5njds2dgvCZMnAIgfjAYEL8MKZTEF6VkpTaFwVcR
D5T5FjM6DHNLuEhwsOU=
-----END CERTIFICATE-----";

    #[test]
    fn a_leaf_with_names_and_an_ip() {
        let c = &parse_pem_bundle(LEAF)[0];
        assert_eq!(c.subject, "O=Fleet Test, CN=api.example.com");
        assert_eq!(c.issuer, "C=IL, O=Fleet Test, CN=Fleet Test CA");
        assert_eq!(c.sans, vec!["api.example.com", "*.api.example.com", "10.0.0.7"]);
        assert_eq!(c.not_before.as_deref(), Some("2026-10-08T18:50:39+00:00"));
        assert_eq!(c.not_after.as_deref(), Some("2026-10-28T18:50:39+00:00"));
        assert!(!c.is_ca);
    }

    #[test]
    fn a_chain_reads_leaf_first_and_knows_its_ca() {
        let chain = parse_pem_bundle(&format!("{LEAF}\n{CA}\n"));
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].subject, chain[1].issuer);
        assert!(chain[1].is_ca);
        assert_eq!(chain[1].not_after.as_deref(), Some("2036-10-05T18:50:39+00:00"));
    }

    #[test]
    fn a_date_past_2049_uses_generalized_time() {
        let c = &parse_pem_bundle(FAR)[0];
        assert_eq!(c.subject, "CN=far.example.com");
        assert_eq!(c.not_after.as_deref(), Some("2054-02-23T18:50:51+00:00"));
    }

    #[test]
    fn a_malformed_time_is_rejected_not_a_panic() {
        // Right byte length, but `é` puts a slice boundary inside a character.
        for (tag, body) in [(0x17, "0\u{e9}000000000Z"), (0x18, "20\u{e9}0000000000Z"), (0x17, "26100818505xZ")] {
            assert_eq!(time(&Tlv { tag, body: body.as_bytes() }), None, "{body}");
        }
        assert_eq!(time(&Tlv { tag: 0x17, body: b"261008185039Z" }).as_deref(), Some("2026-10-08T18:50:39+00:00"));
    }

    #[test]
    fn a_private_key_and_garbage_are_skipped() {
        let text = format!("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n{BEGIN}\nnot base64!\n{END}\n{LEAF}");
        assert_eq!(parse_pem_bundle(&text).len(), 1);
        assert!(parse_der(&[0x30, 0x82, 0xff]).is_none());
        assert!(parse_der(&[]).is_none());
    }
}
