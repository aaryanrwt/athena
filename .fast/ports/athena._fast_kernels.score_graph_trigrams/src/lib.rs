//! Rust port of athena._fast_kernels.score_graph_trigrams (src/athena/_fast_kernels.py).

use pyo3::prelude::*;
use std::collections::{HashMap, HashSet};

#[inline]
fn pack_trigram(c0: u32, c1: u32, c2: u32) -> u128 {
    (3u128 << 96) | ((c0 as u128) << 64) | ((c1 as u128) << 32) | (c2 as u128)
}

fn push_trigrams(text: &str, out: &mut Vec<u128>, char_scratch: &mut Vec<u32>, str_scratch: &mut String) {
    out.clear();
    str_scratch.clear();
    str_scratch.push(' ');
    if text.is_ascii() {
        for &b in text.as_bytes() {
            str_scratch.push((b.to_ascii_lowercase()) as char);
        }
        str_scratch.push(' ');
        let bytes = str_scratch.as_bytes();
        if bytes.len() < 3 {
            let c0 = bytes.first().copied().unwrap_or(0) as u32;
            let c1 = bytes.get(1).copied().unwrap_or(0) as u32;
            out.push(((bytes.len() as u128) << 96) | ((c0 as u128) << 64) | ((c1 as u128) << 32));
        } else {
            out.reserve(bytes.len() - 2);
            for w in bytes.windows(3) {
                out.push(pack_trigram(w[0] as u32, w[1] as u32, w[2] as u32));
            }
            out.sort_unstable();
            out.dedup();
        }
        return;
    }

    for ch in text.chars() {
        for lc in ch.to_lowercase() {
            str_scratch.push(lc);
        }
    }
    str_scratch.push(' ');
    char_scratch.clear();
    char_scratch.extend(str_scratch.chars().map(|c| c as u32));
    if char_scratch.len() < 3 {
        let c0 = char_scratch.first().copied().unwrap_or(0);
        let c1 = char_scratch.get(1).copied().unwrap_or(0);
        out.push(((char_scratch.len() as u128) << 96) | ((c0 as u128) << 64) | ((c1 as u128) << 32));
    } else {
        out.reserve(char_scratch.len() - 2);
        for w in char_scratch.windows(3) {
            out.push(pack_trigram(w[0], w[1], w[2]));
        }
        out.sort_unstable();
        out.dedup();
    }
}

#[inline]
fn sorted_intersection_count(a: &[u128], b: &[u128]) -> usize {
    let mut i = 0usize;
    let mut j = 0usize;
    let mut count = 0usize;
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            count += 1;
            i += 1;
            j += 1;
        } else if a[i] < b[j] {
            i += 1;
        } else {
            j += 1;
        }
    }
    count
}

#[pyfunction]
fn score_graph_trigrams(
    node_ids: Vec<String>,
    labels: Vec<String>,
    file_paths: Vec<String>,
    is_test: Vec<bool>,
    terms: Vec<String>,
    include_tests: bool,
) -> PyResult<(HashMap<String, f64>, Vec<String>)> {
    let n = node_ids
        .len()
        .min(labels.len())
        .min(file_paths.len())
        .min(is_test.len());

    let mut doc_freq: HashMap<&str, usize> = HashMap::with_capacity(terms.len());
    let mut kept_indices: HashMap<String, usize> = HashMap::with_capacity(n);
    let mut docs_nid: Vec<String> = Vec::with_capacity(n);
    let mut docs_label_l: Vec<String> = Vec::with_capacity(n);
    let mut docs_path_l: Vec<String> = Vec::with_capacity(n);
    let mut docs_tri_spans: Vec<(usize, usize)> = Vec::with_capacity(n);
    let mut all_tris: Vec<u128> = Vec::with_capacity(n.saturating_mul(24));

    let mut tri_scratch: Vec<u128> = Vec::with_capacity(64);
    let mut char_scratch: Vec<u32> = Vec::with_capacity(64);
    let mut str_scratch = String::with_capacity(128);
    let mut raw_combo = String::with_capacity(128);

    for i in 0..n {
        if !include_tests && is_test[i] {
            continue;
        }
        let label_l = if labels[i].is_ascii() {
            labels[i].to_ascii_lowercase()
        } else {
            labels[i].to_lowercase()
        };
        let path_l = if file_paths[i].is_ascii() {
            file_paths[i].to_ascii_lowercase()
        } else {
            file_paths[i].to_lowercase()
        };

        raw_combo.clear();
        raw_combo.push_str(&labels[i]);
        raw_combo.push(' ');
        raw_combo.push_str(&file_paths[i]);
        push_trigrams(&raw_combo, &mut tri_scratch, &mut char_scratch, &mut str_scratch);

        for term in &terms {
            if label_l.contains(term.as_str()) || path_l.contains(term.as_str()) {
                *doc_freq.entry(term.as_str()).or_insert(0) += 1;
            }
        }

        let start = all_tris.len();
        all_tris.extend_from_slice(&tri_scratch);
        let span = (start, all_tris.len());

        let nid = &node_ids[i];
        if let Some(&existing_idx) = kept_indices.get(nid.as_str()) {
            docs_label_l[existing_idx] = label_l;
            docs_path_l[existing_idx] = path_l;
            docs_tri_spans[existing_idx] = span;
        } else {
            let idx = docs_nid.len();
            kept_indices.insert(nid.clone(), idx);
            docs_nid.push(nid.clone());
            docs_label_l.push(label_l);
            docs_path_l.push(path_l);
            docs_tri_spans.push(span);
        }
    }

    let total_docs = docs_nid.len().max(1) as f64;
    let mut term_infos: Vec<(&str, f64, Vec<u128>)> = Vec::with_capacity(terms.len());
    for term in &terms {
        let df = doc_freq.get(term.as_str()).copied().unwrap_or(0) as f64;
        let idf = (1.0_f64 + total_docs / (1.0_f64 + df)).ln();
        push_trigrams(term, &mut tri_scratch, &mut char_scratch, &mut str_scratch);
        term_infos.push((term.as_str(), idf, tri_scratch.clone()));
    }

    let mut scores: HashMap<String, f64> = HashMap::new();
    let mut best_by_term: HashMap<usize, (f64, usize)> = HashMap::with_capacity(terms.len());
    let mut term_idx_map: HashMap<&str, usize> = HashMap::with_capacity(terms.len());
    for (idx, t) in terms.iter().enumerate() {
        term_idx_map.entry(t.as_str()).or_insert(idx);
    }

    for doc_idx in 0..docs_nid.len() {
        let (t_start, t_end) = docs_tri_spans[doc_idx];
        let tris = &all_tris[t_start..t_end];
        let label_l = &docs_label_l[doc_idx];
        let path_l = &docs_path_l[doc_idx];
        let mut s = 0.0_f64;

        for (raw_idx, (term_str, idf, t_tris)) in term_infos.iter().enumerate() {
            let canonical_tidx = term_idx_map[term_str];
            let _ = raw_idx;
            let overlap =
                (sorted_intersection_count(tris, t_tris) as f64) / (t_tris.len().max(1) as f64);
            let exact_bonus = if label_l.contains(term_str) {
                2.0_f64
            } else if path_l.contains(term_str) {
                1.0_f64
            } else {
                0.0_f64
            };
            let term_score = (exact_bonus + overlap) * idf;
            s += term_score;
            if term_score > 0.0_f64 {
                match best_by_term.get_mut(&canonical_tidx) {
                    Some(prev) => {
                        if term_score > prev.0 {
                            *prev = (term_score, doc_idx);
                        }
                    }
                    None => {
                        best_by_term.insert(canonical_tidx, (term_score, doc_idx));
                    }
                }
            }
        }
        if s > 0.0_f64 {
            scores.insert(docs_nid[doc_idx].clone(), s);
        }
    }

    let mut best_entries: Vec<(f64, &str)> = best_by_term
        .values()
        .map(|&(sc, didx)| (sc, docs_nid[didx].as_str()))
        .collect();
    best_entries.sort_unstable_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(b.1)));

    let mut seeds: Vec<String> = Vec::with_capacity(8);
    let mut seen_seeds: HashSet<&str> = HashSet::with_capacity(16);
    for (_, nid) in best_entries {
        if seen_seeds.insert(nid) {
            seeds.push(nid.to_string());
        }
    }

    let mut scored_entries: Vec<(f64, &str)> = scores
        .iter()
        .map(|(nid, &sc)| (sc, nid.as_str()))
        .collect();
    scored_entries.sort_unstable_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(b.1)));

    for (_, nid) in scored_entries {
        if seen_seeds.insert(nid) {
            seeds.push(nid.to_string());
        }
        if seeds.len() >= 8 {
            break;
        }
    }

    Ok((scores, seeds))
}

#[pymodule]
fn fa_athena__fast_kernels_score_graph_trigrams(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(score_graph_trigrams, m)?)?;
    Ok(())
}
