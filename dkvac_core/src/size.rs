use crate::instantiation1;
use crate::instantiation2;
use crate::zk::{
    SubsetDelegatableIssueProof, SubsetDelegateProof, SubsetDirectIssueProof,
    VectorDelegatableIssueProof, VectorDelegateProof, VectorDirectIssueProof,
    VectorPresentationProof,
};

pub const POINT_BYTES: usize = 32;
pub const SCALAR_BYTES: usize = 32;
pub const USIZE_BYTES: usize = 8;
pub const SCALAR_KEY_BYTES: usize = 32;

pub fn inst1_credential_size(cred: &instantiation1::Credential) -> usize {
    let _ = cred;
    (2 * POINT_BYTES) + inst1_component_map_size(&cred.components)
}

pub fn inst1_show_size(show: &instantiation1::Show) -> usize {
    (2 * POINT_BYTES) + (show.disclosed.len() * SCALAR_BYTES)
}

pub fn inst1_direct_issue_proof_size(proof: &SubsetDirectIssueProof) -> usize {
    (4 * POINT_BYTES)
        + inst1_component_map_size(&proof.a_components)
        + (3 * SCALAR_BYTES)
}

pub fn inst1_delegatable_issue_proof_size(proof: &SubsetDelegatableIssueProof) -> usize {
    (5 * POINT_BYTES)
        + inst1_component_map_size(&proof.a_components)
        + (4 * SCALAR_BYTES)
}

pub fn inst1_delegate_proof_size(proof: &SubsetDelegateProof) -> usize {
    (3 * POINT_BYTES) + inst1_component_map_size(&proof.a_components) + SCALAR_BYTES
}

pub fn inst1_encdel_size(encdel: &instantiation1::EncDel) -> usize {
    encdel
        .steps
        .iter()
        .map(|step| {
            (3 * POINT_BYTES)
                + inst1_component_map_size(&step.ec.components)
                + match &step.proof {
                    instantiation1::Inst1DelegationProof::Issue(proof) => {
                        inst1_delegatable_issue_proof_size(proof)
                    }
                    instantiation1::Inst1DelegationProof::Delegate(proof) => {
                        inst1_delegate_proof_size(proof)
                    }
                }
        })
        .sum()
}

pub fn inst1_issue_cred_output_size(
    cred: &instantiation1::Credential,
    proof: &SubsetDirectIssueProof,
) -> usize {
    inst1_credential_size(cred) + inst1_direct_issue_proof_size(proof)
}

pub fn inst1_issue_del_output_size(encdel: &instantiation1::EncDel) -> usize {
    inst1_encdel_size(encdel) + SCALAR_BYTES
}

pub fn inst1_delegate_output_size(encdel: &instantiation1::EncDel) -> usize {
    inst1_encdel_size(encdel) + SCALAR_BYTES
}

pub fn inst1_obtain_del_output_size(cred: &instantiation1::Credential) -> usize {
    inst1_credential_size(cred)
}

pub fn inst2_credential_size(cred: &instantiation2::Credential) -> usize {
    (2 * POINT_BYTES)
        + (cred.malleable_keys.len() * (USIZE_BYTES + POINT_BYTES))
        + (cred.message.malleable_indices.len() * USIZE_BYTES)
}

pub fn inst2_show_size(show: &instantiation2::Show) -> usize {
    (2 * POINT_BYTES)
        + (show.q_hidden.len() * (USIZE_BYTES + POINT_BYTES))
        + (show.disclosed.len() * (USIZE_BYTES + SCALAR_BYTES))
        + inst2_vector_presentation_proof_size(&show.proof)
}

pub fn inst2_vector_direct_issue_proof_size(proof: &VectorDirectIssueProof) -> usize {
    (5 * POINT_BYTES)
        + ((proof.a_malleable_keys.len() + proof.a_y.len()) * (USIZE_BYTES + POINT_BYTES))
        + (4 * SCALAR_BYTES)
        + (proof.z_y.len() * (USIZE_BYTES + SCALAR_BYTES))
}

pub fn inst2_vector_delegatable_issue_proof_size(
    proof: &VectorDelegatableIssueProof,
) -> usize {
    (6 * POINT_BYTES)
        + ((proof.a_malleable_keys.len() + proof.a_y.len()) * (USIZE_BYTES + POINT_BYTES))
        + (5 * SCALAR_BYTES)
        + (proof.z_y.len() * (USIZE_BYTES + SCALAR_BYTES))
}

pub fn inst2_vector_presentation_proof_size(proof: &VectorPresentationProof) -> usize {
    POINT_BYTES
        + (proof.a_q.len() * (USIZE_BYTES + POINT_BYTES))
        + SCALAR_BYTES
        + (proof.z_beta.len() * (USIZE_BYTES + SCALAR_BYTES))
        + (proof.z_s.len() * (USIZE_BYTES + SCALAR_BYTES))
}

pub fn inst2_vector_delegate_proof_size(_proof: &VectorDelegateProof) -> usize {
    (3 * POINT_BYTES) + SCALAR_BYTES
}

pub fn inst2_encdel_size(encdel: &instantiation2::EncDel) -> usize {
    encdel
        .steps
        .iter()
        .map(|step| {
            (3 * POINT_BYTES)
                + (step.malleable_keys.len() * (USIZE_BYTES + POINT_BYTES))
                + (step.message.malleable_indices.len() * USIZE_BYTES)
                + match &step.proof {
                    instantiation2::Inst2DelegationProof::Issue(proof) => {
                        inst2_vector_delegatable_issue_proof_size(proof)
                    }
                    instantiation2::Inst2DelegationProof::Delegate(proof) => {
                        inst2_vector_delegate_proof_size(proof)
                    }
                }
        })
        .sum()
}

pub fn inst2_issue_cred_output_size(
    cred: &instantiation2::Credential,
    proof: &VectorDirectIssueProof,
) -> usize {
    inst2_credential_size(cred) + inst2_vector_direct_issue_proof_size(proof)
}

pub fn inst2_issue_del_output_size(encdel: &instantiation2::EncDel) -> usize {
    inst2_encdel_size(encdel) + SCALAR_BYTES
}

pub fn inst2_delegate_output_size(encdel: &instantiation2::EncDel) -> usize {
    inst2_encdel_size(encdel) + SCALAR_BYTES
}

pub fn inst2_obtain_del_output_size(cred: &instantiation2::Credential) -> usize {
    inst2_credential_size(cred)
}

fn inst1_component_map_size<T>(map: &std::collections::BTreeMap<instantiation1::ScalarBytes, T>) -> usize {
    map.len() * (SCALAR_KEY_BYTES + POINT_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{generator, Scalar};
    use crate::instantiation1;
    use crate::instantiation2;
    use crate::zk::{
        VectorDelegatableIssueProof, VectorDirectIssueProof, VectorPresentationProof,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::collections::{BTreeMap, BTreeSet};

    fn scalar(n: u64) -> Scalar {
        Scalar::from(n)
    }

    fn point(n: u64) -> crate::Point {
        scalar(n) * generator()
    }

    #[test]
    fn inst1_credential_with_4_attributes_has_expected_size() {
        let components = [1u64, 2, 3, 4]
            .into_iter()
            .map(|n| (instantiation1::ScalarBytes(scalar(n).to_bytes()), point(n + 10)))
            .collect::<BTreeMap<_, _>>();
        let cred = instantiation1::Credential {
            v_x_g: point(1),
            ev: point(2),
            components,
        };
        assert_eq!(inst1_credential_size(&cred), 2 * POINT_BYTES + 4 * (SCALAR_KEY_BYTES + POINT_BYTES));
    }

    #[test]
    fn inst1_show_with_4_disclosed_attributes_has_expected_size() {
        let show = instantiation1::Show {
            v_prime: point(1),
            c_prime: point(2),
            disclosed: vec![scalar(1), scalar(2), scalar(3), scalar(4)],
        };
        assert_eq!(inst1_show_size(&show), (2 * POINT_BYTES) + (4 * SCALAR_BYTES));
    }

    #[test]
    fn inst2_credential_with_4_attributes_and_4_malleable_indices_has_expected_size() {
        let cred = instantiation2::Credential {
            v_g: point(1),
            c: point(2),
            malleable_keys: BTreeMap::from([
                (0usize, point(3)),
                (1usize, point(4)),
                (2usize, point(5)),
                (3usize, point(6)),
            ]),
            message: instantiation2::Message {
                attributes: vec![scalar(1), scalar(2), scalar(3), scalar(4)],
                malleable_indices: BTreeSet::from([0usize, 1, 2, 3]),
            },
        };
        assert_eq!(
            inst2_credential_size(&cred),
            (2 * POINT_BYTES) + (4 * (USIZE_BYTES + POINT_BYTES)) + (4 * USIZE_BYTES)
        );
    }

    #[test]
    fn inst2_direct_issue_proof_counts_all_fields() {
        let proof = VectorDirectIssueProof {
            a_v: point(1),
            a_c: point(2),
            a_malleable_keys: BTreeMap::from([(1usize, point(3)), (3usize, point(4))]),
            a_r: point(5),
            a_r_inv: point(6),
            a_x: point(7),
            a_y: BTreeMap::from([(1usize, point(8)), (3usize, point(9))]),
            z_r_inv: scalar(10),
            z_r: scalar(11),
            z_x: scalar(12),
            z_y: BTreeMap::from([(1usize, scalar(13)), (3usize, scalar(14))]),
            z_v: scalar(15),
        };
        let fixed_points = 5 * POINT_BYTES;
        let indexed_points = 4 * (USIZE_BYTES + POINT_BYTES);
        let fixed_scalars = 4 * SCALAR_BYTES;
        let indexed_scalars = 2 * (USIZE_BYTES + SCALAR_BYTES);
        assert_eq!(
            inst2_vector_direct_issue_proof_size(&proof),
            fixed_points + indexed_points + fixed_scalars + indexed_scalars
        );
    }

    #[test]
    fn inst2_delegatable_issue_proof_counts_all_fields() {
        let proof = VectorDelegatableIssueProof {
            a_ev: point(1),
            a_ez: point(2),
            a_c: point(3),
            a_malleable_keys: BTreeMap::from([(1usize, point(4)), (3usize, point(5))]),
            a_r: point(6),
            a_r_inv: point(7),
            a_x: point(8),
            a_y: BTreeMap::from([(1usize, point(9)), (3usize, point(10))]),
            z_r_inv: scalar(11),
            z_r: scalar(12),
            z_x: scalar(13),
            z_y: BTreeMap::from([(1usize, scalar(14)), (3usize, scalar(15))]),
            z_v: scalar(16),
            z_z: scalar(17),
        };
        let fixed_points = 6 * POINT_BYTES;
        let indexed_points = 4 * (USIZE_BYTES + POINT_BYTES);
        let fixed_scalars = 5 * SCALAR_BYTES;
        let indexed_scalars = 2 * (USIZE_BYTES + SCALAR_BYTES);
        assert_eq!(
            inst2_vector_delegatable_issue_proof_size(&proof),
            fixed_points + indexed_points + fixed_scalars + indexed_scalars
        );
    }

    #[test]
    fn inst2_full_disclosure_show_with_4_attributes_has_expected_size() {
        let show = instantiation2::Show {
            v_prime: point(1),
            w: point(2),
            q_hidden: BTreeMap::new(),
            disclosed: BTreeMap::from([
                (0usize, scalar(1)),
                (1usize, scalar(2)),
                (2usize, scalar(3)),
                (3usize, scalar(4)),
            ]),
            proof: VectorPresentationProof {
                a_p: point(5),
                a_q: BTreeMap::new(),
                z_mu_prime: scalar(6),
                z_beta: BTreeMap::new(),
                z_s: BTreeMap::new(),
            },
        };
        let expected_show = (2 * POINT_BYTES) + (4 * (USIZE_BYTES + SCALAR_BYTES));
        let expected_proof = POINT_BYTES + SCALAR_BYTES;
        assert_eq!(inst2_show_size(&show), expected_show + expected_proof);
    }

    #[test]
    fn encdel_size_increases_after_delegation_for_both_constructions() {
        let mut rng1 = ChaCha20Rng::from_seed([7u8; 32]);
        let pp1 = instantiation1::setup(&mut rng1);
        let (isk1, ipar1) = instantiation1::keygen(&mut rng1, &pp1).expect("keygen1");
        let attrs1 = vec![scalar(1), scalar(2), scalar(3), scalar(4)];
        let (encdel1, dk1) =
            instantiation1::issue_del(&mut rng1, &pp1, &isk1, &ipar1, &attrs1).expect("issue del1");
        let before1 = inst1_encdel_size(&encdel1);
        let (encdel1_after, _) =
            instantiation1::delegate(&mut rng1, &encdel1, &dk1, &[scalar(1), scalar(2), scalar(3)])
                .expect("delegate1");
        assert!(inst1_encdel_size(&encdel1_after) > before1);

        let mut rng2 = ChaCha20Rng::from_seed([9u8; 32]);
        let pp2 = instantiation2::setup(&mut rng2, 4);
        let (isk2, ipar2) = instantiation2::keygen(&mut rng2, &pp2).expect("keygen2");
        let msg2 = instantiation2::Message {
            attributes: vec![scalar(3), scalar(5), scalar(7), scalar(11)],
            malleable_indices: BTreeSet::from([0usize, 1, 2, 3]),
        };
        let (encdel2, dk2) =
            instantiation2::issue_del(&mut rng2, &pp2, &isk2, &ipar2, &msg2).expect("issue del2");
        let before2 = inst2_encdel_size(&encdel2);
        let next2 = instantiation2::Message {
            attributes: msg2.attributes.clone(),
            malleable_indices: BTreeSet::from([0usize, 1, 2]),
        };
        let (encdel2_after, _) =
            instantiation2::delegate(&mut rng2, &pp2, &encdel2, &dk2, &next2).expect("delegate2");
        assert!(inst2_encdel_size(&encdel2_after) > before2);
    }
}
