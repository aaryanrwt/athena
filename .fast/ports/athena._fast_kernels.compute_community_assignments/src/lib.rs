//! Rust port of athena._fast_kernels.compute_community_assignments (src/athena/_fast_kernels.py).

use pyo3::exceptions::PyKeyError;
use pyo3::prelude::*;
use std::collections::HashMap;

struct NodeMeta {
    nid: String,
    is_test: bool,
    label: String,
}

#[pyfunction]
fn compute_community_assignments(
    node_ids: Vec<String>,
    node_is_test: Vec<bool>,
    node_labels: Vec<String>,
    edges: Vec<(String, String, String, f64, String)>,
) -> PyResult<(HashMap<String, i64>, HashMap<String, String>)> {
    if node_ids.is_empty() {
        return Ok((HashMap::new(), HashMap::new()));
    }

    let label_len = node_ids.len().min(node_labels.len());
    let test_len = node_ids.len().min(node_is_test.len());
    if label_len == 0 {
        return Ok((HashMap::new(), HashMap::new()));
    }

    let mut is_test_map: HashMap<String, bool> = HashMap::with_capacity(test_len);
    for (nid, &t) in node_ids.iter().zip(node_is_test.iter()) {
        is_test_map.insert(nid.clone(), t);
    }

    let mut label_dedup: HashMap<String, (String, bool)> = HashMap::with_capacity(label_len);
    for i in 0..label_len {
        let nid = &node_ids[i];
        let is_t = match is_test_map.get(nid.as_str()) {
            Some(&v) => v,
            None => return Err(PyKeyError::new_err(nid.clone())),
        };
        label_dedup.insert(nid.clone(), (node_labels[i].clone(), is_t));
    }

    let mut nodes: Vec<NodeMeta> = label_dedup
        .into_iter()
        .map(|(nid, (label, is_test))| NodeMeta {
            nid,
            is_test,
            label,
        })
        .collect();
    nodes.sort_unstable_by(|a, b| a.nid.cmp(&b.nid));

    let n = nodes.len();
    let mut id_to_idx: HashMap<&str, usize> = HashMap::with_capacity(n);
    for (idx, meta) in nodes.iter().enumerate() {
        id_to_idx.insert(meta.nid.as_str(), idx);
    }

    struct FilteredEdge<'a> {
        src: usize,
        tgt: usize,
        rel: &'a str,
        weight: f64,
    }

    let mut valid_edges: Vec<FilteredEdge<'_>> = Vec::with_capacity(edges.len());
    for (src_s, tgt_s, rel_s, weight, conf_s) in &edges {
        if src_s == tgt_s {
            continue;
        }
        if let (Some(&src), Some(&tgt)) = (
            id_to_idx.get(src_s.as_str()),
            id_to_idx.get(tgt_s.as_str()),
        ) {
            let factor = if conf_s == "inferred" { 0.5_f64 } else { 1.0_f64 };
            valid_edges.push(FilteredEdge {
                src,
                tgt,
                rel: rel_s.as_str(),
                weight: weight * factor,
            });
        }
    }

    // Match Python stable sort by (source, target, relation)
    valid_edges.sort_by(|a, b| {
        a.src
            .cmp(&b.src)
            .then_with(|| a.tgt.cmp(&b.tgt))
            .then_with(|| a.rel.cmp(b.rel))
    });

    let mut adj: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n];
    for e in valid_edges {
        adj[e.src].push((e.tgt, e.weight));
        adj[e.tgt].push((e.src, e.weight));
    }

    let mut comm: Vec<usize> = (0..n).collect();
    let mut epoch_tag: Vec<u32> = vec![0; n];
    let mut epoch_sum: Vec<f64> = vec![0.0; n];
    let mut touched: Vec<usize> = Vec::with_capacity(64);
    let mut epoch: u32 = 1;

    for _ in 0..12 {
        let mut changed = false;
        for nid in 0..n {
            let neighbors = &adj[nid];
            if neighbors.is_empty() {
                continue;
            }
            epoch = epoch.wrapping_add(1);
            if epoch == 0 {
                epoch_tag.fill(0);
                epoch = 1;
            }
            touched.clear();
            for &(nb, w) in neighbors {
                let c = comm[nb];
                if epoch_tag[c] != epoch {
                    epoch_tag[c] = epoch;
                    epoch_sum[c] = w;
                    touched.push(c);
                } else {
                    epoch_sum[c] += w;
                }
            }
            let mut best_c = touched[0];
            let mut best_s = epoch_sum[best_c];
            for &c in &touched[1..] {
                let s = epoch_sum[c];
                // Match Python `min(scores.items(), key=lambda item: (-item[1], item[0]))`
                if (-s < -best_s) || (-s == -best_s && c < best_c) {
                    best_s = s;
                    best_c = c;
                }
            }
            if best_c != comm[nid] {
                comm[nid] = best_c;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut group_slots: Vec<isize> = vec![-1; n];
    let mut groups: Vec<Vec<usize>> = Vec::with_capacity(n.min(256));
    for nid in 0..n {
        let c = comm[nid];
        let slot = group_slots[c];
        if slot < 0 {
            group_slots[c] = groups.len() as isize;
            groups.push(vec![nid]);
        } else {
            groups[slot as usize].push(nid);
        }
    }

    groups.sort_unstable_by(|a, b| b.len().cmp(&a.len()).then_with(|| a[0].cmp(&b[0])));

    let mut final_comm: HashMap<String, i64> = HashMap::with_capacity(n);
    let mut community_labels: HashMap<String, String> = HashMap::with_capacity(groups.len());

    for (cid, members) in groups.iter().enumerate() {
        for &m in members {
            final_comm.insert(nodes[m].nid.clone(), cid as i64);
        }
        let mut hub = members[0];
        let mut hub_key = (
            if nodes[hub].is_test { 1u8 } else { 0u8 },
            -(adj[hub].len() as isize),
            hub,
        );
        for &m in &members[1..] {
            let k = (
                if nodes[m].is_test { 1u8 } else { 0u8 },
                -(adj[m].len() as isize),
                m,
            );
            if k < hub_key {
                hub = m;
                hub_key = k;
            }
        }
        community_labels.insert(cid.to_string(), nodes[hub].label.clone());
    }

    Ok((final_comm, community_labels))
}

#[pymodule]
fn fa_athena__fast_kernels_compute_community_assignments(
    m: &Bound<'_, PyModule>,
) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(compute_community_assignments, m)?)?;
    Ok(())
}
