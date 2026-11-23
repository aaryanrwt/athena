//! Rust port of athena._fast_kernels.extract_structural_symbols_raw (src/athena/_fast_kernels.py).

use pyo3::prelude::*;
use regex::Regex;
use std::sync::OnceLock;

struct PyLines<'a> {
    rest: &'a str,
}

impl<'a> Iterator for PyLines<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        if self.rest.is_ascii() {
            let bytes = self.rest.as_bytes();
            for (i, &b) in bytes.iter().enumerate() {
                if matches!(b, b'\n' | b'\r' | 0x0b | 0x0c | 0x1c | 0x1d | 0x1e) {
                    let line = &self.rest[..i];
                    let skip = if b == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
                        2
                    } else {
                        1
                    };
                    self.rest = &self.rest[i + skip..];
                    return Some(line);
                }
            }
            let line = self.rest;
            self.rest = "";
            return Some(line);
        }

        for (i, ch) in self.rest.char_indices() {
            if matches!(
                ch,
                '\n' | '\r'
                    | '\u{000b}'
                    | '\u{000c}'
                    | '\u{001c}'
                    | '\u{001d}'
                    | '\u{001e}'
                    | '\u{0085}'
                    | '\u{2028}'
                    | '\u{2029}'
            ) {
                let line = &self.rest[..i];
                let ch_len = ch.len_utf8();
                let skip = if ch == '\r' && self.rest[i + 1..].starts_with('\n') {
                    2
                } else {
                    ch_len
                };
                self.rest = &self.rest[i + skip..];
                return Some(line);
            }
        }
        let line = self.rest;
        self.rest = "";
        Some(line)
    }
}

#[inline]
fn py_lstrip(s: &str) -> &str {
    s.trim_start_matches(|c: char| c.is_whitespace() || matches!(c, '\u{001c}'..='\u{001f}'))
}

struct StructuralRegexes {
    ts: Vec<Regex>,
    js: Vec<Regex>,
    go: Vec<Regex>,
    rust: Vec<Regex>,
    java: Vec<Regex>,
    kotlin: Vec<Regex>,
    ruby: Vec<Regex>,
    php: Vec<Regex>,
    csharp: Vec<Regex>,
    c: Vec<Regex>,
    cpp: Vec<Regex>,
    cuda: Vec<Regex>,
    tex: Vec<Regex>,
    imp_ts: Regex,
    imp_js: Regex,
    imp_go: Regex,
    imp_rust: Regex,
    ts_js_reexport: Regex,
    php_dynamic: Regex,
}

fn compile_all(pats: &[&str]) -> Vec<Regex> {
    pats.iter().map(|p| Regex::new(p).unwrap()).collect()
}

fn get_regexes() -> &'static StructuralRegexes {
    static RE: OnceLock<StructuralRegexes> = OnceLock::new();
    RE.get_or_init(|| StructuralRegexes {
        ts: compile_all(&[
            r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*[<(]",
            r"^\s*(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)",
            r"^\s*(?:export\s+)?interface\s+([A-Za-z_$][A-Za-z0-9_$]*)",
            r"^\s*(?:export\s+)?type\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=",
            r"^\s*(?:export\s+)?const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(",
        ]),
        js: compile_all(&[
            r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
            r"^\s*(?:export\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)",
            r"^\s*(?:export\s+)?const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(",
            r"^\s*(?:module\.)?exports\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=",
        ]),
        go: compile_all(&[
            r"^\s*func\s+(?:\([^)]+\)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            r"^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\s+(?:struct|interface)\b",
        ]),
        rust: compile_all(&[
            r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]",
            r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait)\s+([A-Za-z_][A-Za-z0-9_]*)",
        ]),
        java: compile_all(&[
            r"^\s*(?:public|protected|private)?\s*(?:static\s+|final\s+|abstract\s+)*(?:class|interface|enum|record)\s+([A-Za-z_][A-Za-z0-9_]*)",
        ]),
        kotlin: compile_all(&[
            r"^\s*(?:public|internal|private|protected)?\s*(?:suspend\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]",
            r"^\s*(?:data\s+|sealed\s+)?(?:class|interface|object)\s+([A-Za-z_][A-Za-z0-9_]*)",
        ]),
        ruby: compile_all(&[
            r"^\s*def\s+(?:self\.)?([A-Za-z_][A-Za-z0-9_]*[!?=]?)",
            r"^\s*(?:class|module)\s+([A-Za-z_][A-Za-z0-9_:]*)",
        ]),
        php: compile_all(&[
            r"^\s*(?:public|protected|private)?\s*(?:static\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            r"^\s*(?:abstract\s+|final\s+)?(?:class|interface|trait)\s+([A-Za-z_][A-Za-z0-9_]*)",
        ]),
        csharp: compile_all(&[
            r"^\s*(?:public|internal|private|protected)?\s*(?:static\s+|sealed\s+|abstract\s+|partial\s+)*(?:class|interface|struct|record|enum)\s+([A-Za-z_][A-Za-z0-9_]*)",
        ]),
        c: compile_all(&[r"^\s*(?:typedef\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)"]),
        cpp: compile_all(&[r"^\s*(?:class|struct|namespace)\s+([A-Za-z_][A-Za-z0-9_]*)"]),
        cuda: compile_all(&[
            r"^\s*(?:__global__|__device__|__host__)(?:\s+(?:__device__|__host__|inline|static))*\s+[A-Za-z_][A-Za-z0-9_:<>*&\s]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            r"^\s*(?:class|struct|namespace)\s+([A-Za-z_][A-Za-z0-9_]*)",
        ]),
        tex: compile_all(&[
            r"^\s*\\(?:sub)*section\*?\{([^}]+)\}",
            r"^\s*\\newcommand\*?\{\\([A-Za-z0-9_]+)\}",
        ]),
        imp_ts: Regex::new(r#"^\s*import\s+.*?\s+from\s+['"]([^'"]+)['"]"#).unwrap(),
        imp_js: Regex::new(r#"^\s*(?:import\s+.*?\s+from\s+|require\s*\(\s*)['"]([^'"]+)['"]"#)
            .unwrap(),
        imp_go: Regex::new(r#"^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?["']([^"']+)["']"#).unwrap(),
        imp_rust: Regex::new(r"^\s*use\s+([A-Za-z0-9_:]+);").unwrap(),
        ts_js_reexport: Regex::new(r#"^\s*export\s+(?:\*|\{[^}]+\})\s+from\s+['"]([^'"]+)['"]"#)
            .unwrap(),
        php_dynamic: Regex::new(
            r"(?:__callStatic|__call|->\s*(?:bind|singleton)\s*\(|app\s*\(\s*\)\s*->\s*make\s*\()",
        )
        .unwrap(),
    })
}

#[pyfunction]
fn extract_structural_symbols_raw(
    language: &str,
    source: &str,
) -> PyResult<(Vec<(String, i64)>, Vec<String>, Vec<i64>)> {
    let reg = get_regexes();
    let patterns: &[Regex] = match language {
        "typescript" => &reg.ts,
        "javascript" => &reg.js,
        "go" => &reg.go,
        "rust" => &reg.rust,
        "java" => &reg.java,
        "kotlin" => &reg.kotlin,
        "ruby" => &reg.ruby,
        "php" => &reg.php,
        "csharp" => &reg.csharp,
        "c" => &reg.c,
        "cpp" => &reg.cpp,
        "cuda" => &reg.cuda,
        "tex" => &reg.tex,
        _ => &[],
    };
    let imp_pat: Option<&Regex> = match language {
        "typescript" => Some(&reg.imp_ts),
        "javascript" => Some(&reg.imp_js),
        "go" => Some(&reg.imp_go),
        "rust" => Some(&reg.imp_rust),
        _ => None,
    };
    let is_ts_js = language == "typescript" || language == "javascript";
    let is_php = language == "php";

    let mut symbols: Vec<(String, i64)> = Vec::new();
    let mut import_targets: Vec<String> = Vec::new();
    let mut php_dynamic_lines: Vec<i64> = Vec::new();

    for (zero_idx, line) in (PyLines { rest: source }).enumerate() {
        let idx = (zero_idx + 1) as i64;
        let char_len = if line.is_ascii() {
            line.len()
        } else {
            line.chars().count()
        };
        if char_len > 512 {
            continue;
        }
        let stripped = py_lstrip(line);
        if stripped.is_empty()
            || stripped.starts_with("//")
            || stripped.starts_with('#')
            || stripped.starts_with("/*")
            || stripped.starts_with('*')
            || stripped.starts_with("--")
        {
            continue;
        }
        if let Some(ip) = imp_pat {
            if let Some(cap) = ip.captures(line) {
                if let Some(m) = cap.get(1) {
                    import_targets.push(m.as_str().to_owned());
                }
            }
        }
        if is_ts_js {
            if let Some(cap) = reg.ts_js_reexport.captures(line) {
                if let Some(m) = cap.get(1) {
                    import_targets.push(m.as_str().to_owned());
                }
            }
        }
        if is_php && reg.php_dynamic.is_match(line) {
            php_dynamic_lines.push(idx);
        }
        for pat in patterns {
            if let Some(cap) = pat.captures(line) {
                if let Some(m) = cap.get(1) {
                    let sym = m.as_str();
                    if !sym.is_empty() {
                        symbols.push((sym.to_owned(), idx));
                    }
                }
                break;
            }
        }
    }

    Ok((symbols, import_targets, php_dynamic_lines))
}

#[pymodule]
fn fa_athena__fast_kernels_extract_structural_symbols_raw(
    m: &Bound<'_, PyModule>,
) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_structural_symbols_raw, m)?)?;
    Ok(())
}
