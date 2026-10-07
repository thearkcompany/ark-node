//! Subjective Local Trust Graph & Sybil-Resistant Personalized PageRank (ACP-04).

use std::collections::{HashMap, VecDeque};
use serde::{Deserialize, Serialize};

/// Discrete Trust Tiers mapped deterministically from score S and hop distance d.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustTier {
    /// Untrusted: score < 0.15 or unreachable. Strict rate-limits, VPN denied by default.
    Untrusted,
    /// Probationary: 0.15 <= score < 0.50, distance <= 4. Moderate rate-limits, small PoW.
    Probationary,
    /// Trusted: 0.50 <= score < 0.85, distance <= 2. Preferential relay and storage access.
    Trusted,
    /// CorePeer: score >= 0.85, distance <= 1. Full access, zero restriction.
    CorePeer,
}

impl Default for TrustTier {
    fn default() -> Self {
        Self::Untrusted
    }
}

/// Evaluation result for a target identity relative to the local node's root.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustEvaluation {
    pub target: [u8; 32],
    pub score: f64,
    pub distance: u32,
    pub tier: TrustTier,
}

impl TrustEvaluation {
    /// Deterministic derivation of TrustTier from continuous score and topological distance.
    pub fn derive_tier(score: f64, distance: u32) -> TrustTier {
        if score >= 0.85 && distance <= 1 {
            TrustTier::CorePeer
        } else if score >= 0.50 && distance <= 2 {
            TrustTier::Trusted
        } else if score >= 0.15 && distance <= 4 {
            TrustTier::Probationary
        } else {
            TrustTier::Untrusted
        }
    }
}

/// Subjective directed trust graph rooted at local node's ArkId.
#[derive(Debug, Clone)]
pub struct LocalTrustGraph {
    pub local_root: [u8; 32],
    /// Adjacency: issuer -> (subject -> raw_weight)
    adj: HashMap<[u8; 32], HashMap<[u8; 32], f64>>,
    /// Cached Personalized PageRank scores
    ppr_scores: HashMap<[u8; 32], f64>,
    /// Cached shortest path distances from local_root
    distances: HashMap<[u8; 32], u32>,
}

impl LocalTrustGraph {
    pub fn new(local_root: [u8; 32]) -> Self {
        let mut ppr_scores = HashMap::new();
        ppr_scores.insert(local_root, 1.0);

        let mut distances = HashMap::new();
        distances.insert(local_root, 0);

        Self {
            local_root,
            adj: HashMap::new(),
            ppr_scores,
            distances,
        }
    }

    /// Add or update a directed trust edge from issuer to subject with weight w in [0.0, 1.0].
    pub fn add_edge(&mut self, issuer: [u8; 32], subject: [u8; 32], weight: f64) {
        if weight <= 0.0 {
            return;
        }
        let clamped = weight.clamp(0.0, 1.0);
        self.adj.entry(issuer).or_default().insert(subject, clamped);
    }

    /// Remove a directed edge (e.g. on revocation).
    pub fn remove_edge(&mut self, issuer: &[u8; 32], subject: &[u8; 32]) {
        if let Some(neighbors) = self.adj.get_mut(issuer) {
            neighbors.remove(subject);
        }
    }

    /// Compute shortest path distances from local_root using BFS, bounded to max distance (d <= 6).
    pub fn compute_distances(&mut self) {
        let mut dists = HashMap::new();
        dists.insert(self.local_root, 0);

        let mut queue = VecDeque::new();
        queue.push_back((self.local_root, 0));

        while let Some((node, d)) = queue.pop_front() {
            if d >= 6 {
                continue;
            }
            if let Some(neighbors) = self.adj.get(&node) {
                for &neighbor in neighbors.keys() {
                    if !dists.contains_key(&neighbor) {
                        dists.insert(neighbor, d + 1);
                        queue.push_back((neighbor, d + 1));
                    }
                }
            }
        }

        self.distances = dists;
    }

    /// Compute Personalized PageRank (PPR) using power-iteration with damping factor alpha = 0.85
    /// and stochastic out-degree normalization (sum w_out <= 1.0).
    pub fn compute_ppr(&mut self) {
        self.compute_distances();

        // Collect reachable nodes within horizon d <= 6
        let reachable_nodes: Vec<[u8; 32]> = self.distances.keys().copied().collect();
        if reachable_nodes.is_empty() {
            return;
        }

        let alpha = 0.85f64;
        let epsilon = 1e-5f64;
        let max_iterations = 50;

        // Build stochastic transition matrix with out-degree normalization
        let mut norm_trans: HashMap<[u8; 32], HashMap<[u8; 32], f64>> = HashMap::new();
        for &u in &reachable_nodes {
            if let Some(neighbors) = self.adj.get(&u) {
                let valid_neighbors: HashMap<[u8; 32], f64> = neighbors
                    .iter()
                    .filter(|(v, _)| self.distances.contains_key(*v))
                    .map(|(v, w)| (*v, *w))
                    .collect();

                let sum_w: f64 = valid_neighbors.values().sum();
                if sum_w > 0.0 {
                    let mut norm_map = HashMap::new();
                    // Stochastic normalization: if sum_w > 1.0, scale down so sum is 1.0
                    // If sum_w <= 1.0, preserve individual weights
                    let divisor = if sum_w > 1.0 { sum_w } else { 1.0 };
                    for (v, w) in valid_neighbors {
                        norm_map.insert(v, w / divisor);
                    }
                    norm_trans.insert(u, norm_map);
                }
            }
        }

        // Initialize PPR vector: restart distribution centered 100% on local_root
        let mut p: HashMap<[u8; 32], f64> = HashMap::new();
        for &node in &reachable_nodes {
            p.insert(node, if node == self.local_root { 1.0 } else { 0.0 });
        }

        // Power-iteration
        for _ in 0..max_iterations {
            let mut p_next: HashMap<[u8; 32], f64> = HashMap::new();
            for &node in &reachable_nodes {
                p_next.insert(node, 0.0);
            }

            // Distribute probability along normalized edges
            let mut accumulated_leak = 0.0f64;
            for (&u, &p_u) in &p {
                if p_u <= 0.0 {
                    continue;
                }
                if let Some(edges) = norm_trans.get(&u) {
                    let mut total_out = 0.0f64;
                    for (&v, &w) in edges {
                        *p_next.entry(v).or_default() += alpha * p_u * w;
                        total_out += w;
                    }
                    // Remaining weight or unallocated fraction leaks back to local_root
                    accumulated_leak += alpha * p_u * (1.0 - total_out).max(0.0);
                } else {
                    // Dangling node: entire alpha leaks back to root
                    accumulated_leak += alpha * p_u;
                }
            }

            // Add teleport probability (1 - alpha) and accumulated leaks to local_root
            *p_next.entry(self.local_root).or_default() += (1.0 - alpha) + accumulated_leak;

            // Check convergence
            let mut max_diff = 0.0f64;
            for &node in &reachable_nodes {
                let diff = (p_next.get(&node).copied().unwrap_or(0.0) - p.get(&node).copied().unwrap_or(0.0)).abs();
                if diff > max_diff {
                    max_diff = diff;
                }
            }

            p = p_next;
            if max_diff < epsilon {
                break;
            }
        }

        // Scale scores so that local_root is 1.0
        let root_score = p.get(&self.local_root).copied().unwrap_or(1.0);
        let mut normalized_scores = HashMap::new();
        for (node, score) in p {
            let s = if root_score > 0.0 { (score / root_score).clamp(0.0, 1.0) } else { 0.0 };
            normalized_scores.insert(node, s);
        }

        self.ppr_scores = normalized_scores;
    }

    /// Evaluate trust for any target ArkId.
    pub fn evaluate_trust(&self, target: &[u8; 32]) -> TrustEvaluation {
        if target == &self.local_root {
            return TrustEvaluation {
                target: *target,
                score: 1.0,
                distance: 0,
                tier: TrustTier::CorePeer,
            };
        }

        let score = self.ppr_scores.get(target).copied().unwrap_or(0.0);
        let distance = self.distances.get(target).copied().unwrap_or(u32::MAX);
        let tier = TrustEvaluation::derive_tier(score, distance);

        TrustEvaluation {
            target: *target,
            score,
            distance,
            tier,
        }
    }
}
