//! Cross-layer regressions for the paper-v2 migration.
use dkvac_core::{
    Point, Scalar, error::DkvacError, instantiation1 as sub, instantiation2 as vec, size, zk::*,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroize;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([81; 32])
}
fn attributes() -> Vec<Scalar> {
    (1u64..=4).map(Scalar::from).collect()
}
fn message() -> vec::Message {
    vec::Message {
        attributes: attributes(),
        malleable_indices: BTreeSet::from([0, 1, 2, 3]),
    }
}

#[test]
fn both_delegates_sample_and_apply_independent_nonzero_masks() {
    let mut rng = rng();
    let pp = sub::setup(&mut rng);
    let (isk, ipar) = sub::keygen(&mut rng, &pp).unwrap();
    let root = sub::issue_del(&mut rng, &pp, &isk, &ipar, &attributes()).unwrap();
    let mut predicted = rng.clone();
    let mu = dkvac_core::random_scalar(&mut predicted);
    let z = dkvac_core::random_scalar(&mut predicted);
    let next = sub::delegate(&mut rng, &pp, &root, &attributes()).unwrap();
    assert_ne!(z, Scalar::ZERO);
    assert_eq!(next.dk, mu * root.dk + z);
    assert_eq!(next.steps[1].ec.e, mu * root.steps[0].ec.e + z * pp.h);
    assert_eq!(next.steps[1].ec.ev, mu * root.steps[0].ec.ev);
    assert_eq!(next.steps[1].ec.ez, mu * root.steps[0].ec.ez + z * pp.g);
    let pp = vec::setup(&mut rng, 4);
    let (isk, ipar) = vec::keygen(&mut rng, &pp).unwrap();
    let root = vec::issue_del(&mut rng, &pp, &isk, &ipar, &message()).unwrap();
    let mut predicted = rng.clone();
    let mu = dkvac_core::random_scalar(&mut predicted);
    let z = dkvac_core::random_scalar(&mut predicted);
    let next = vec::delegate(&mut rng, &pp, &root, &message()).unwrap();
    assert_ne!(z, Scalar::ZERO);
    assert_eq!(next.dk, mu * root.dk + z);
    assert_eq!(next.steps[1].ec.ev, mu * root.steps[0].ec.ev + z * pp.h);
    assert_eq!(next.steps[1].ec.ez, mu * root.steps[0].ec.ez + z * pp.g);
}

#[test]
fn subset_wrong_keys_fail_at_every_depth_and_serde_retains_only_current_key() {
    let mut rng = rng();
    let pp = sub::setup(&mut rng);
    let (isk, ipar) = sub::keygen(&mut rng, &pp).unwrap();
    let mut chain = sub::issue_del(&mut rng, &pp, &isk, &ipar, &attributes()).unwrap();
    for depth in 0..4 {
        let bytes = bincode::serialize(&chain).unwrap();
        let restored: sub::EncDel = bincode::deserialize(&bytes).unwrap();
        assert_eq!(restored.dk, chain.dk);
        assert_eq!(restored.steps.len(), depth + 1);
        assert_eq!(
            bytes.len(),
            bincode::serialized_size(&chain.steps).unwrap() as usize + 32
        );
        assert!(format!("{restored:?}").contains("[REDACTED]"));
        let cred = sub::obtain_del(&pp, &ipar, &restored).unwrap();
        let show = sub::show_cred(&mut rng, &cred, &attributes()[..1]).unwrap();
        assert!(sub::verify_show(&isk, &show).unwrap());
        let mut wrong = restored.clone();
        wrong.dk += Scalar::ONE;
        assert!(sub::obtain_del(&pp, &ipar, &wrong).is_err());
        wrong.zeroize();
        assert_eq!(wrong.dk, Scalar::ZERO);
        chain = sub::delegate(&mut rng, &pp, &chain, &attributes()[..4 - depth.min(2)]).unwrap();
    }
}

#[test]
fn vector_wrong_keys_fail_at_every_depth_and_serde_retains_only_current_key() {
    let mut rng = rng();
    let pp = vec::setup(&mut rng, 4);
    let (isk, ipar) = vec::keygen(&mut rng, &pp).unwrap();
    let mut msg = message();
    let mut chain = vec::issue_del(&mut rng, &pp, &isk, &ipar, &msg).unwrap();
    for depth in 0..4 {
        let bytes = bincode::serialize(&chain).unwrap();
        let restored: vec::EncDel = bincode::deserialize(&bytes).unwrap();
        assert_eq!(restored, chain);
        assert_eq!(
            bytes.len(),
            bincode::serialized_size(&chain.steps).unwrap() as usize + 32
        );
        assert!(format!("{restored:?}").contains("[REDACTED]"));
        let cred = vec::obtain_del(&pp, &ipar, &restored).unwrap();
        for indices in [
            BTreeSet::new(),
            BTreeSet::from([1, 3]),
            BTreeSet::from([0, 1, 2, 3]),
        ] {
            let policy = vec::DisclosurePolicy {
                disclosed_indices: indices,
            };
            let show = vec::show_cred(&mut rng, &pp, &ipar, &cred.message, &policy, &cred).unwrap();
            assert!(vec::verify_show(&pp, &ipar, &isk, &policy, &show).unwrap());
        }
        let mut wrong = restored.clone();
        wrong.dk += Scalar::ONE;
        assert!(vec::obtain_del(&pp, &ipar, &wrong).is_err());
        wrong.zeroize();
        assert_eq!(wrong.dk, Scalar::ZERO);
        msg.attributes[depth] += Scalar::ONE;
        msg.malleable_indices.remove(&depth);
        chain = vec::delegate(&mut rng, &pp, &chain, &msg).unwrap();
    }
    assert!(
        vec::obtain_del(&pp, &ipar, &chain)
            .unwrap()
            .malleable_keys
            .is_empty()
    );
}

#[test]
fn vector_predicate_only_allows_changes_when_finalizing() {
    let mut rng = rng();
    let pp = vec::setup(&mut rng, 4);
    let (isk, ipar) = vec::keygen(&mut rng, &pp).unwrap();
    let msg = message();
    let chain = vec::issue_del(&mut rng, &pp, &isk, &ipar, &msg).unwrap();
    let mut next = msg.clone();
    next.attributes[1] += Scalar::ONE;
    assert!(!vec::is_valid_delegation(&msg, &next));
    assert!(vec::delegate(&mut rng, &pp, &chain, &next).is_err());
    next.malleable_indices.remove(&1);
    let delegated = vec::delegate(&mut rng, &pp, &chain, &next).unwrap();
    let mut forged = delegated.clone();
    forged.steps.last_mut().unwrap().message.attributes[2] += Scalar::ONE;
    assert!(matches!(
        vec::obtain_del(&pp, &ipar, &forged),
        Err(DkvacError::InvalidDelegation)
    ));
    let mut malformed = msg.clone();
    malformed.malleable_indices.insert(99);
    assert!(!vec::is_valid_delegation(&malformed, &next));
    malformed.attributes.pop();
    assert!(!vec::is_valid_delegation(&malformed, &next));
}

#[test]
fn vector_retained_key_and_proof_variant_tampering_fails() {
    let mut rng = rng();
    let pp = vec::setup(&mut rng, 4);
    let (isk, ipar) = vec::keygen(&mut rng, &pp).unwrap();
    let msg = message();
    let root = vec::issue_del(&mut rng, &pp, &isk, &ipar, &msg).unwrap();
    let chain = vec::delegate(&mut rng, &pp, &root, &msg).unwrap();
    for mode in 0..5 {
        let mut bad = chain.clone();
        match mode {
            0 => *bad.steps[1].malleable_keys.get_mut(&1).unwrap() += pp.g,
            1 => bad.steps[1].ec.ez += pp.g,
            2 => bad.steps[1].proof = bad.steps[0].proof.clone(),
            3 => bad.steps[0].proof = bad.steps[1].proof.clone(),
            _ => {
                bad.steps[1].malleable_keys.remove(&1);
            }
        }
        assert!(vec::obtain_del(&pp, &ipar, &bad).is_err());
    }
}

#[test]
fn subset_proof_variant_and_key_handle_tampering_fails() {
    let mut rng = rng();
    let pp = sub::setup(&mut rng);
    let (isk, ipar) = sub::keygen(&mut rng, &pp).unwrap();
    let root = sub::issue_del(&mut rng, &pp, &isk, &ipar, &attributes()).unwrap();
    let chain = sub::delegate(&mut rng, &pp, &root, &attributes()).unwrap();
    for mode in 0..3 {
        let mut bad = chain.clone();
        match mode {
            0 => bad.steps[1].ec.ez += pp.g,
            1 => bad.steps[1].proof = bad.steps[0].proof.clone(),
            _ => bad.steps[0].proof = bad.steps[1].proof.clone(),
        }
        assert!(sub::obtain_del(&pp, &ipar, &bad).is_err());
    }
}

#[test]
fn subset_valid_cancelling_aggregate_is_accepted() {
    let mut rng = rng();
    let pp = sub::setup(&mut rng);
    let (isk, ipar) = sub::keygen(&mut rng, &pp).unwrap();
    let attrs = [Scalar::ONE - isk.y, -Scalar::ONE - isk.y];
    let (cred, proof) = sub::issue_cred(&mut rng, &pp, &isk, &ipar, &attrs).unwrap();
    let cred = sub::obtain_cred(&ipar, &attrs, cred, &proof).unwrap();
    let show = sub::show_cred(&mut rng, &cred, &attrs).unwrap();
    assert_eq!(show.c_prime, Point::default());
    assert_ne!(show.v_prime, Point::default());
    assert!(sub::verify_show(&isk, &show).unwrap());
    assert!(sub::show_cred(&mut rng, &cred, &[]).is_err());
}

#[test]
fn subset_zero_updated_key_is_allowed_and_fresh_mask_equations_hold() {
    let mut rng = rng();
    let pp = sub::setup(&mut rng);
    let (isk, ipar) = sub::keygen(&mut rng, &pp).unwrap();
    let mut chain = sub::issue_del(&mut rng, &pp, &isk, &ipar, &attributes()).unwrap();
    let old = chain.steps.last().unwrap().clone();
    let mu = Scalar::from(7u64);
    let z_prime = -mu * chain.dk;
    assert_ne!(z_prime, Scalar::ZERO);
    let ec = sub::EncryptedCredential {
        e: mu * old.ec.e + z_prime * pp.h,
        ev: mu * old.ec.ev,
        ez: mu * old.ec.ez + z_prime * pp.g,
        components: old
            .ec
            .components
            .iter()
            .map(|(k, p)| (*k, mu * p))
            .collect(),
    };
    let statement = SubsetDelegateStatement {
        g: pp.g,
        h: pp.h,
        old_e: old.ec.e,
        old_ev: old.ec.ev,
        old_ez: old.ec.ez,
        old_components: old.ec.components.clone(),
        new_e: ec.e,
        new_ev: ec.ev,
        new_ez: ec.ez,
        new_components: ec.components.clone(),
    };
    let proof =
        SubsetDelegateProof::prove(&mut rng, &statement, &SubsetDelegateWitness { mu, z_prime });
    chain.steps.push(sub::DelegationStep {
        ec,
        attributes: old.attributes,
        proof: sub::Inst1DelegationProof::Delegate(proof),
    });
    chain.dk = Scalar::ZERO;
    let cred = sub::obtain_del(&pp, &ipar, &chain).unwrap();
    assert_eq!(
        cred.v_x_g,
        mu * (old.ec.e - (-z_prime * mu.invert()) * pp.h)
    );
    let show = sub::show_cred(&mut rng, &cred, &attributes()).unwrap();
    assert!(sub::verify_show(&isk, &show).unwrap());
}

#[test]
fn vector_zero_updated_key_allowed_but_zero_plaintext_delegation_rejected() {
    let mut rng = rng();
    let pp = vec::setup(&mut rng, 4);
    let (isk, ipar) = vec::keygen(&mut rng, &pp).unwrap();
    let msg = message();
    let root = vec::issue_del(&mut rng, &pp, &isk, &ipar, &msg).unwrap();
    for mu in [Scalar::from(7u64), Scalar::ZERO] {
        let mut chain = root.clone();
        let old = &root.steps[0];
        let z_prime = if mu == Scalar::ZERO {
            Scalar::ONE
        } else {
            -mu * root.dk
        };
        let dk = mu * root.dk + z_prime;
        let ec = vec::EncryptedCredential {
            ev: mu * old.ec.ev + z_prime * pp.h,
            ez: mu * old.ec.ez + z_prime * pp.g,
            c: mu * old.ec.c,
        };
        let keys: BTreeMap<_, _> = old
            .malleable_keys
            .iter()
            .map(|(i, p)| (*i, mu * p))
            .collect();
        let s = VectorDelegateStatement {
            g: pp.g,
            h: pp.h,
            old_ev: old.ec.ev,
            old_ez: old.ec.ez,
            old_c: old.ec.c,
            old_message: msg.clone(),
            new_message: msg.clone(),
            old_malleable_keys: old.malleable_keys.clone(),
            new_malleable_keys: keys.clone(),
            new_ev: ec.ev,
            new_ez: ec.ez,
            new_c: ec.c,
        };
        let proof =
            VectorDelegateProof::prove(&mut rng, &s, &VectorDelegateWitness { mu, z_prime });
        assert!(proof.verify(&s));
        chain.steps.push(vec::DelegationStep {
            ec,
            malleable_keys: keys,
            message: msg.clone(),
            proof: vec::Inst2DelegationProof::Delegate(proof),
        });
        chain.dk = dk;
        if mu == Scalar::ZERO {
            assert!(matches!(
                vec::obtain_del(&pp, &ipar, &chain),
                Err(DkvacError::IdentityPoint)
            ));
        } else {
            assert_eq!(chain.dk, Scalar::ZERO);
            let cred = vec::obtain_del(&pp, &ipar, &chain).unwrap();
            let policy = vec::DisclosurePolicy {
                disclosed_indices: BTreeSet::new(),
            };
            let show = vec::show_cred(&mut rng, &pp, &ipar, &msg, &policy, &cred).unwrap();
            assert!(vec::verify_show(&pp, &ipar, &isk, &policy, &show).unwrap());
        }
    }
}

#[test]
fn vector_obtain_checks_plaintext_not_ciphertext_nonidentity() {
    let mut rng = rng();
    // A known H/G ratio is used only to construct the ciphertext-cancellation
    // edge case in this test; production setup must not expose that ratio.
    let g = dkvac_core::group::generator();
    let pp = vec::PublicParams {
        g,
        h: Scalar::from(17u64) * g,
        max_attributes: 4,
    };
    let (isk, ipar) = vec::keygen(&mut rng, &pp).unwrap();
    let msg = message();
    for v in [Scalar::ZERO, Scalar::from(19u64)] {
        let z = if v == Scalar::ZERO {
            Scalar::ONE
        } else {
            -v * Scalar::from(17u64).invert()
        };
        let y_powers: BTreeMap<_, _> = (0..4).map(|i| (i, vec::y_power(&isk.y, i))).collect();
        let s = VectorDelegatableIssueStatement {
            g,
            h: pp.h,
            r_h: ipar.r_h,
            r_x_g: ipar.r_x_g,
            r_y_i_g: ipar.r_y_i_g.clone(),
            ev: v * g + z * pp.h,
            ez: z * g,
            c: vec::compute_mac_scalar(&isk, &msg).unwrap() * v * g,
            attributes: msg.attributes.clone(),
            malleable_indices: msg.malleable_indices.clone(),
            malleable_keys: y_powers.iter().map(|(i, y)| (*i, v * y * g)).collect(),
        };
        let proof = VectorDelegatableIssueProof::prove(
            &mut rng,
            &s,
            &VectorDelegatableIssueWitness {
                r_inv: isk.r.invert(),
                r: isk.r,
                x: isk.x,
                y_powers,
                v,
                z,
            },
        );
        assert!(proof.verify(&s));
        let chain = vec::EncDel {
            dk: z,
            steps: vec![vec::DelegationStep {
                ec: vec::EncryptedCredential {
                    ev: s.ev,
                    ez: s.ez,
                    c: s.c,
                },
                malleable_keys: s.malleable_keys,
                message: msg.clone(),
                proof: vec::Inst2DelegationProof::Issue(proof),
            }],
        };
        if v == Scalar::ZERO {
            assert!(matches!(
                vec::obtain_del(&pp, &ipar, &chain),
                Err(DkvacError::IdentityPoint)
            ));
        } else {
            assert_eq!(s.ev, Point::default());
            assert_eq!(vec::obtain_del(&pp, &ipar, &chain).unwrap().v_g, v * g);
        }
    }
}

#[test]
fn v2_proof_sizes_and_whole_object_key_accounting() {
    let mut rng = rng();
    let pp = sub::setup(&mut rng);
    let (isk, ipar) = sub::keygen(&mut rng, &pp).unwrap();
    let root = sub::issue_del(&mut rng, &pp, &isk, &ipar, &attributes()).unwrap();
    let chain = sub::delegate(&mut rng, &pp, &root, &attributes()[..2]).unwrap();
    let sub::Inst1DelegationProof::Delegate(proof) = &chain.steps[1].proof else {
        panic!()
    };
    assert_eq!(size::inst1_delegate_proof_size(proof), 160 + 64 * 2);
    assert_eq!(
        size::inst1_encdel_size(&chain),
        size::inst1_encdel_size(&root) + 96 + 96 * 2 + 160 + 64 * 2
    );
    assert_eq!(
        size::inst1_delegate_output_size(&chain),
        size::inst1_encdel_size(&chain)
    );
    let pp = vec::setup(&mut rng, 4);
    let (isk, ipar) = vec::keygen(&mut rng, &pp).unwrap();
    for indices in [
        BTreeSet::new(),
        BTreeSet::from([1, 3]),
        BTreeSet::from([0, 1, 2, 3]),
    ] {
        let msg = vec::Message {
            malleable_indices: indices,
            ..message()
        };
        let (_, proof) = vec::issue_cred(&mut rng, &pp, &isk, &ipar, &msg).unwrap();
        let m = msg.malleable_indices.len();
        assert_eq!(
            size::inst2_vector_direct_issue_proof_size(&proof),
            288 + 40 * m + 80 * 4
        );
        let root = vec::issue_del(&mut rng, &pp, &isk, &ipar, &msg).unwrap();
        let vec::Inst2DelegationProof::Issue(proof) = &root.steps[0].proof else {
            panic!()
        };
        assert_eq!(
            size::inst2_vector_delegatable_issue_proof_size(proof),
            352 + 40 * m + 80 * 4
        );
        let chain = vec::delegate(&mut rng, &pp, &root, &msg).unwrap();
        let vec::Inst2DelegationProof::Delegate(proof) = &chain.steps[1].proof else {
            panic!()
        };
        assert_eq!(size::inst2_vector_delegate_proof_size(proof), 160 + 40 * m);
        assert_eq!(
            size::inst2_encdel_size(&chain),
            size::inst2_encdel_size(&root) + 96 + 48 * m + 32 * 4 + 160 + 40 * m
        );
        assert_eq!(
            size::inst2_delegate_output_size(&chain),
            size::inst2_encdel_size(&chain)
        );
    }
}
