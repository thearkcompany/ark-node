use ark_crypto::fn_dsa::FnDsaKeyPair;
use ark_crypto::identity::Identity;
use ark_wot::crypto::{CapabilityScopes, TrustAttestation};
use ark_wot::graph::{LocalTrustGraph, TrustTier};
use rand::rngs::OsRng;

#[test]
fn test_trust_graph_ppr_and_tier_derivation() {
    let mut rng = OsRng;
    let local_key = FnDsaKeyPair::generate(&mut rng);
    let peer_a_key = FnDsaKeyPair::generate(&mut rng);
    let peer_b_key = FnDsaKeyPair::generate(&mut rng);

    let local_id = Identity::from_public_key(&local_key.public_key).ark_id;
    let peer_a = Identity::from_public_key(&peer_a_key.public_key).ark_id;
    let peer_b = Identity::from_public_key(&peer_b_key.public_key).ark_id;

    let mut graph = LocalTrustGraph::new(local_id);

    // Local node evaluates itself as CorePeer (score 1.0, distance 0)
    let self_eval = graph.evaluate_trust(&local_id);
    assert_eq!(self_eval.tier, TrustTier::CorePeer);
    assert_eq!(self_eval.distance, 0);
    assert!((self_eval.score - 1.0).abs() < 1e-4);

    // Direct edge: local -> peer_a with weight 0.95
    let att_a = TrustAttestation::create_and_sign(
        local_id,
        peer_a,
        0.95,
        CapabilityScopes::empty(),
        1000,
        1000 + 30 * 86400,
        1,
        &local_key,
    )
    .unwrap();
    graph.add_edge(att_a.issuer_id, att_a.subject_id, 0.95);

    // Edge: peer_a -> peer_b with weight 0.8
    let att_b = TrustAttestation::create_and_sign(
        peer_a,
        peer_b,
        0.8,
        CapabilityScopes::empty(),
        1000,
        1000 + 30 * 86400,
        2,
        &peer_a_key,
    )
    .unwrap();
    graph.add_edge(att_b.issuer_id, att_b.subject_id, 0.8);

    graph.compute_ppr();

    let eval_a = graph.evaluate_trust(&peer_a);
    assert_eq!(eval_a.distance, 1);
    assert!(eval_a.score >= 0.50, "peer_a score: {}", eval_a.score);
    assert!(matches!(
        eval_a.tier,
        TrustTier::CorePeer | TrustTier::Trusted
    ));

    let eval_b = graph.evaluate_trust(&peer_b);
    assert_eq!(eval_b.distance, 2);
    assert!(eval_b.score > 0.15, "peer_b score: {}", eval_b.score);

    // Unconnected random node
    let unknown_id = [0xEE; 32];
    let eval_unknown = graph.evaluate_trust(&unknown_id);
    assert_eq!(eval_unknown.tier, TrustTier::Untrusted);
    assert_eq!(eval_unknown.score, 0.0);
}

#[test]
fn test_sybil_collusion_ring_resistance() {
    let mut rng = OsRng;
    let local_key = FnDsaKeyPair::generate(&mut rng);
    let honest_peer_key = FnDsaKeyPair::generate(&mut rng);
    let sybil_entry_key = FnDsaKeyPair::generate(&mut rng);

    let local_id = Identity::from_public_key(&local_key.public_key).ark_id;
    let honest_peer = Identity::from_public_key(&honest_peer_key.public_key).ark_id;
    let sybil_entry = Identity::from_public_key(&sybil_entry_key.public_key).ark_id;

    let mut graph = LocalTrustGraph::new(local_id);

    // Strong edge to honest peer
    graph.add_edge(local_id, honest_peer, 0.9);
    // Small edge to sybil entry
    graph.add_edge(local_id, sybil_entry, 0.1);

    // Generate dense Sybil collusion cluster of 20 nodes
    let mut sybil_nodes = Vec::new();
    sybil_nodes.push(sybil_entry);
    for _ in 0..19 {
        let k = FnDsaKeyPair::generate(&mut rng);
        sybil_nodes.push(Identity::from_public_key(&k.public_key).ark_id);
    }

    // Dense mesh within Sybil cluster
    for i in 0..sybil_nodes.len() {
        for j in 0..sybil_nodes.len() {
            if i != j {
                graph.add_edge(sybil_nodes[i], sybil_nodes[j], 1.0);
            }
        }
    }

    graph.compute_ppr();

    // Sybil nodes inside cluster cannot inflate their score beyond entry bottleneck
    let eval_entry = graph.evaluate_trust(&sybil_entry);
    for s_node in &sybil_nodes[1..] {
        let eval_s = graph.evaluate_trust(s_node);
        assert!(
            eval_s.score <= eval_entry.score + 0.01,
            "Sybil internal node score {} exceeded bottleneck {}",
            eval_s.score,
            eval_entry.score
        );
        assert_ne!(eval_s.tier, TrustTier::CorePeer);
    }
}
