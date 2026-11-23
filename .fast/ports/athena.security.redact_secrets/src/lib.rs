//! Rust port of athena.security.redact_secrets (src/athena/security.py).

use pyo3::prelude::*;
use regex::Regex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::OnceLock;

struct SecretRegexes {
    uri_userinfo: Regex,
    auth_cred: Regex,
    github_pat: Regex,
    github_fine_pat: Regex,
    anthropic_key: Regex,
    openai_key: Regex,
    google_api_key: Regex,
    slack_token: Regex,
    aws_access_key: Regex,
    private_key_block: Regex,
    generic_secret: Regex,
}

fn get_regexes() -> &'static SecretRegexes {
    static REGEXES: OnceLock<SecretRegexes> = OnceLock::new();
    REGEXES.get_or_init(|| SecretRegexes {
        uri_userinfo: Regex::new(
            r"(?i)\b(?P<scheme>https?|ftp)://(?P<username>[^\s/@:]+):(?P<password>[^\s/@]+)@",
        )
        .unwrap(),
        auth_cred: Regex::new(r"(?i)\b(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+").unwrap(),
        github_pat: Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b").unwrap(),
        github_fine_pat: Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{35,255}\b").unwrap(),
        anthropic_key: Regex::new(r"\bsk-ant-[A-Za-z0-9\-_]{20,255}\b").unwrap(),
        openai_key: Regex::new(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9\-_]{20,255}\b").unwrap(),
        google_api_key: Regex::new(r"\bAIzaSy[A-Za-z0-9\-_]{33}\b").unwrap(),
        slack_token: Regex::new(r"\bxox[baprs]-[A-Za-z0-9\-]{10,255}\b").unwrap(),
        aws_access_key: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
        private_key_block: Regex::new(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        )
        .unwrap(),
        generic_secret: Regex::new(
            r#"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|client[_-]?secret)\s*[:=]\s*['"]([^'"]{8,120})['"]"#,
        )
        .unwrap(),
    })
}

#[inline]
fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[inline]
fn contains_ascii_ci(hay: &[u8], lower_needle: &[u8]) -> bool {
    if hay.len() < lower_needle.len() {
        return false;
    }
    hay.windows(lower_needle.len())
        .any(|w| w.iter().zip(lower_needle).all(|(&a, &b)| a.to_ascii_lowercase() == b))
}

#[inline]
fn apply_regex<'a>(cow: Cow<'a, str>, re: &Regex, repl: &str) -> Cow<'a, str> {
    if re.is_match(cow.as_ref()) {
        Cow::Owned(re.replace_all(cow.as_ref(), repl).into_owned())
    } else {
        cow
    }
}

#[inline]
fn shannon_entropy_bytes(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 128];
    for &b in bytes {
        if (b as usize) < 128 {
            counts[b as usize] += 1;
        } else {
            return shannon_entropy_unicode_fallback(bytes);
        }
    }
    let len = bytes.len() as f64;
    let mut sum = 0.0_f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            sum -= p * p.log2();
        }
    }
    sum
}

fn shannon_entropy_unicode_fallback(bytes: &[u8]) -> f64 {
    let s = std::str::from_utf8(bytes).unwrap_or("");
    let mut counts: HashMap<char, u32> = HashMap::new();
    let mut len = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        len += 1;
    }
    if len == 0 {
        return 0.0;
    }
    let lf = len as f64;
    let mut sum = 0.0_f64;
    for &c in counts.values() {
        let p = (c as f64) / lf;
        sum -= p * p.log2();
    }
    sum
}

#[inline]
fn is_quoted_literal_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

fn redact_quoted_high_entropy<'a>(cow: Cow<'a, str>) -> Cow<'a, str> {
    let bytes = cow.as_bytes();
    if bytes.len() < 30 || (!bytes.contains(&b'\'') && !bytes.contains(&b'"')) {
        return cow;
    }

    let mut out: Option<String> = None;
    let mut last_copied = 0usize;
    let mut i = 0usize;
    let n = bytes.len();

    while i + 29 < n {
        let b = bytes[i];
        if b == b'\'' || b == b'"' {
            let mut j = i + 1;
            let limit = (i + 1 + 128).min(n);
            while j < limit && is_quoted_literal_byte(bytes[j]) {
                j += 1;
            }
            let cand_len = j - (i + 1);
            if cand_len >= 28 && j < n && bytes[j] == b {
                // If 128 bytes reached and next byte is still in class, wait: j == i+129 and bytes[j] == b means len=128 exact!
                // Otherwise regex cannot match starting at i because >128 bytes wouldn't fit {28,128}\1.
                let cand = &bytes[i + 1..j];
                let has_slash_or_dot = cand.contains(&b'/');
                if !has_slash_or_dot {
                    let all_alpha = cand.iter().all(|c| c.is_ascii_alphabetic());
                    let all_digit = cand.iter().all(|c| c.is_ascii_digit());
                    if !all_alpha && !all_digit {
                        let has_upper = cand.iter().any(|c| c.is_ascii_uppercase());
                        let has_lower = cand.iter().any(|c| c.is_ascii_lowercase());
                        let has_digit = cand.iter().any(|c| c.is_ascii_digit());
                        if has_upper && has_lower && has_digit && shannon_entropy_bytes(cand) > 4.5 {
                            let buf = out.get_or_insert_with(|| String::with_capacity(n + 32));
                            buf.push_str(&cow[last_copied..i]);
                            buf.push(b as char);
                            buf.push_str("[REDACTED_HIGH_ENTROPY_SECRET]");
                            buf.push(b as char);
                            last_copied = j + 1;
                        }
                    }
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }

    match out {
        Some(mut buf) => {
            buf.push_str(&cow[last_copied..]);
            Cow::Owned(buf)
        }
        None => cow,
    }
}

#[pyfunction]
fn redact_secrets<'py>(text: &'py str) -> PyResult<Cow<'py, str>> {
    if text.is_empty() {
        return Ok(Cow::Borrowed(""));
    }
    if text.len() < 10 {
        return Ok(Cow::Borrowed(text));
    }

    let res = get_regexes();
    let mut current: Cow<'py, str> = Cow::Borrowed(text);

    {
        let b = current.as_bytes();
        if b.contains(&b'@') && contains_bytes(b, b"://") {
            current = apply_regex(
                current,
                &res.uri_userinfo,
                "${scheme}://${username}:[REDACTED_URI_CREDENTIAL]@",
            );
        }
    }
    if current.as_bytes().contains(&b':') && contains_ascii_ci(current.as_bytes(), b"authorization") {
        current = apply_regex(
            current,
            &res.auth_cred,
            "${1}[REDACTED_AUTHORIZATION_CREDENTIAL]",
        );
    }
    if current.as_bytes().contains(&b'_') && contains_bytes(current.as_bytes(), b"gh") {
        current = apply_regex(current, &res.github_pat, "[REDACTED_GITHUB_PAT]");
    }
    if contains_bytes(current.as_bytes(), b"github_pat_") {
        current = apply_regex(current, &res.github_fine_pat, "[REDACTED_GITHUB_FINE_PAT]");
    }
    if contains_bytes(current.as_bytes(), b"sk-ant-") {
        current = apply_regex(current, &res.anthropic_key, "[REDACTED_ANTHROPIC_KEY]");
    }
    if contains_bytes(current.as_bytes(), b"sk-") {
        current = apply_regex(current, &res.openai_key, "[REDACTED_OPENAI_KEY]");
    }
    if contains_bytes(current.as_bytes(), b"AIzaSy") {
        current = apply_regex(current, &res.google_api_key, "[REDACTED_GOOGLE_API_KEY]");
    }
    if contains_bytes(current.as_bytes(), b"xox") {
        current = apply_regex(current, &res.slack_token, "[REDACTED_SLACK_TOKEN]");
    }
    if contains_bytes(current.as_bytes(), b"AKIA") || contains_bytes(current.as_bytes(), b"ASIA") {
        current = apply_regex(current, &res.aws_access_key, "[REDACTED_AWS_ACCESS_KEY]");
    }
    if contains_bytes(current.as_bytes(), b"-----BEGIN ") {
        current = apply_regex(
            current,
            &res.private_key_block,
            "[REDACTED_PRIVATE_KEY_BLOCK]",
        );
    }
    {
        let b = current.as_bytes();
        if (b.contains(&b'\'') || b.contains(&b'"')) && (b.contains(&b':') || b.contains(&b'=')) {
            current = apply_regex(current, &res.generic_secret, "${1} = '[REDACTED_SECRET]'");
        }
    }

    current = redact_quoted_high_entropy(current);
    Ok(current)
}

#[pymodule]
fn fa_athena_security_redact_secrets(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(redact_secrets, m)?)?;
    Ok(())
}
