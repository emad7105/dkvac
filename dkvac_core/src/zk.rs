use crate::group::{Point, Scalar, is_identity, random_scalar};
use crate::instantiation1::ScalarBytes;
use crate::instantiation2::{Message, is_valid_delegation};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub fn transcript_append_point(transcript: &mut Transcript, label: &'static [u8], point: &Point) {
    transcript.append_message(label, point.compress().as_bytes());
}

pub fn transcript_append_scalar(
    transcript: &mut Transcript,
    label: &'static [u8],
    scalar: &Scalar,
) {
    transcript.append_message(label, &scalar.to_bytes());
}

pub fn transcript_append_usize(transcript: &mut Transcript, label: &'static [u8], value: usize) {
    transcript.append_message(label, &(value as u64).to_le_bytes());
}

pub fn transcript_challenge_scalar(transcript: &mut Transcript, label: &'static [u8]) -> Scalar {
    let mut buf = [0u8; 64];
    transcript.challenge_bytes(label, &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubsetDelegateStatement {
    pub g: Point,
    pub h: Point,
    pub old_e: Point,
    pub old_ev: Point,
    pub old_ez: Point,
    pub old_components: BTreeMap<ScalarBytes, Point>,
    pub new_e: Point,
    pub new_ev: Point,
    pub new_ez: Point,
    pub new_components: BTreeMap<ScalarBytes, Point>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubsetDelegateWitness {
    pub mu: Scalar,
    pub z_prime: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsetDelegateProof {
    pub a_e: Point,
    pub a_ev: Point,
    pub a_ez: Point,
    pub a_components: BTreeMap<ScalarBytes, Point>,
    pub z_mu: Scalar,
    pub z_z_prime: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubsetDirectIssueStatement {
    pub g: Point,
    pub x_g: Point,
    pub y_g: Point,
    pub v_x_g: Point,
    pub ev: Point,
    pub components: BTreeMap<ScalarBytes, Point>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubsetDirectIssueWitness {
    pub x: Scalar,
    pub y: Scalar,
    pub v: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsetDirectIssueProof {
    pub a_x: Point,
    pub a_y: Point,
    pub a_ev: Point,
    pub a_v: Point,
    pub a_components: BTreeMap<ScalarBytes, Point>,
    pub z_x: Scalar,
    pub z_y: Scalar,
    pub z_v: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubsetDelegatableIssueStatement {
    pub g: Point,
    pub h: Point,
    pub x_g: Point,
    pub y_g: Point,
    pub e: Point,
    pub ev: Point,
    pub ez: Point,
    pub components: BTreeMap<ScalarBytes, Point>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubsetDelegatableIssueWitness {
    pub x: Scalar,
    pub y: Scalar,
    pub v: Scalar,
    pub z: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsetDelegatableIssueProof {
    pub a_x: Point,
    pub a_y: Point,
    pub a_ev: Point,
    pub a_ez: Point,
    pub a_e: Point,
    pub a_components: BTreeMap<ScalarBytes, Point>,
    pub z_x: Scalar,
    pub z_y: Scalar,
    pub z_v: Scalar,
    pub z_z: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorDelegateStatement {
    pub g: Point,
    pub h: Point,
    pub old_ev: Point,
    pub old_ez: Point,
    pub old_c: Point,
    pub old_message: Message,
    pub new_message: Message,
    pub old_malleable_keys: BTreeMap<usize, Point>,
    pub new_malleable_keys: BTreeMap<usize, Point>,
    pub new_ev: Point,
    pub new_ez: Point,
    pub new_c: Point,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorDelegateWitness {
    pub mu: Scalar,
    pub z_prime: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorDelegateProof {
    pub a_ev: Point,
    pub a_ez: Point,
    pub a_c: Point,
    pub a_malleable_keys: BTreeMap<usize, Point>,
    pub z_mu: Scalar,
    pub z_z_prime: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorPresentationStatement {
    pub g: Point,
    pub h: Point,
    pub r_h: Point,
    pub r_x_g: Point,
    pub r_y_i_g: Vec<Point>,
    pub v_prime: Point,
    pub p: Point,
    pub q_hidden: BTreeMap<usize, Point>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorPresentationWitness {
    pub mu_prime: Scalar,
    pub hidden_attributes: BTreeMap<usize, Scalar>,
    pub beta: BTreeMap<usize, Scalar>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorPresentationProof {
    pub a_p: Point,
    pub a_q: BTreeMap<usize, Point>,
    pub z_mu_prime: Scalar,
    pub z_beta: BTreeMap<usize, Scalar>,
    pub z_s: BTreeMap<usize, Scalar>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorDirectIssueStatement {
    pub g: Point,
    pub h: Point,
    pub r_h: Point,
    pub r_x_g: Point,
    pub r_y_i_g: Vec<Point>,
    pub v_g: Point,
    pub c: Point,
    pub attributes: Vec<Scalar>,
    pub malleable_keys: BTreeMap<usize, Point>,
    pub malleable_indices: BTreeSet<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorDirectIssueWitness {
    pub r_inv: Scalar,
    pub r: Scalar,
    pub x: Scalar,
    pub y_i: BTreeMap<usize, Scalar>,
    pub v: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorDirectIssueProof {
    pub a_v: Point,
    pub a_c: Point,
    pub a_malleable_keys: BTreeMap<usize, Point>,
    pub a_r: Point,
    pub a_r_inv: Point,
    pub a_x: Point,
    pub a_y: BTreeMap<usize, Point>,
    pub z_r_inv: Scalar,
    pub z_r: Scalar,
    pub z_x: Scalar,
    pub z_y: BTreeMap<usize, Scalar>,
    pub z_v: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorDelegatableIssueStatement {
    pub g: Point,
    pub h: Point,
    pub r_h: Point,
    pub r_x_g: Point,
    pub r_y_i_g: Vec<Point>,
    pub ev: Point,
    pub ez: Point,
    pub c: Point,
    pub attributes: Vec<Scalar>,
    pub malleable_keys: BTreeMap<usize, Point>,
    pub malleable_indices: BTreeSet<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorDelegatableIssueWitness {
    pub r_inv: Scalar,
    pub r: Scalar,
    pub x: Scalar,
    pub y_i: BTreeMap<usize, Scalar>,
    pub v: Scalar,
    pub z: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorDelegatableIssueProof {
    pub a_ev: Point,
    pub a_ez: Point,
    pub a_c: Point,
    pub a_malleable_keys: BTreeMap<usize, Point>,
    pub a_r: Point,
    pub a_r_inv: Point,
    pub a_x: Point,
    pub a_y: BTreeMap<usize, Point>,
    pub z_r_inv: Scalar,
    pub z_r: Scalar,
    pub z_x: Scalar,
    pub z_y: BTreeMap<usize, Scalar>,
    pub z_v: Scalar,
    pub z_z: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorIssueProofPlaceholder {
    pub warning: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorIssuePaperProofPlaceholder {
    pub warning: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorIssueOption3Statement {
    pub g: Point,
    pub x_g: Point,
    pub y_i_g: Vec<Point>,
    pub v_g: Point,
    pub c: Point,
    pub attributes: Vec<Scalar>,
    pub y_power_points: Vec<Point>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorIssueOption3Witness {
    pub x: Scalar,
    pub v: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorIssueOption3Proof {
    pub a_x: Point,
    pub a_v: Point,
    pub a_c: Point,
    pub a_y_power_points: Vec<Point>,
    pub z_x: Scalar,
    pub z_v: Scalar,
}

impl SubsetDelegateProof {
    pub fn prove<R: CryptoRng + RngCore>(
        rng: &mut R,
        statement: &SubsetDelegateStatement,
        witness: &SubsetDelegateWitness,
    ) -> Self {
        let rho = random_scalar(rng);
        let rho_z = random_scalar(rng);
        let a_e = rho * statement.old_e + rho_z * statement.h;
        let a_ev = rho * statement.old_ev;
        let a_ez = rho * statement.old_ez + rho_z * statement.g;
        let a_components = statement
            .new_components
            .keys()
            .map(|key| (*key, rho * statement.old_components[key]))
            .collect::<BTreeMap<_, _>>();

        let mut transcript = Transcript::new(b"dkvac-subset-delegate-v2");
        append_subset_delegate_statement(&mut transcript, statement);
        transcript_append_point(&mut transcript, b"a_e", &a_e);
        transcript_append_point(&mut transcript, b"a_ev", &a_ev);
        transcript_append_point(&mut transcript, b"a_ez", &a_ez);
        for (key, point) in &a_components {
            transcript.append_message(b"a_component_key", &key.0);
            transcript_append_point(&mut transcript, b"a_component_value", point);
        }
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        Self {
            a_e,
            a_ev,
            a_ez,
            a_components,
            z_mu: rho + c * witness.mu,
            z_z_prime: rho_z + c * witness.z_prime,
        }
    }

    pub fn verify(&self, statement: &SubsetDelegateStatement) -> bool {
        if is_identity(&statement.new_ev)
            || statement.new_components.is_empty()
            || statement.new_components.len() != self.a_components.len()
        {
            return false;
        }

        let mut transcript = Transcript::new(b"dkvac-subset-delegate-v2");
        append_subset_delegate_statement(&mut transcript, statement);
        transcript_append_point(&mut transcript, b"a_e", &self.a_e);
        transcript_append_point(&mut transcript, b"a_ev", &self.a_ev);
        transcript_append_point(&mut transcript, b"a_ez", &self.a_ez);
        for (key, point) in &self.a_components {
            transcript.append_message(b"a_component_key", &key.0);
            transcript_append_point(&mut transcript, b"a_component_value", point);
        }
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        if self.z_mu * statement.old_e + self.z_z_prime * statement.h
            != self.a_e + c * statement.new_e
        {
            return false;
        }
        if self.z_mu * statement.old_ev != self.a_ev + c * statement.new_ev {
            return false;
        }
        if self.z_mu * statement.old_ez + self.z_z_prime * statement.g
            != self.a_ez + c * statement.new_ez
        {
            return false;
        }

        for (key, new_component) in &statement.new_components {
            let Some(old_component) = statement.old_components.get(key) else {
                return false;
            };
            let Some(a_component) = self.a_components.get(key) else {
                return false;
            };
            if self.z_mu * *old_component != *a_component + c * *new_component {
                return false;
            }
        }

        true
    }
}

impl SubsetDirectIssueProof {
    pub fn prove<R: CryptoRng + RngCore>(
        rng: &mut R,
        statement: &SubsetDirectIssueStatement,
        witness: &SubsetDirectIssueWitness,
    ) -> Self {
        let rho_x = random_scalar(rng);
        let rho_y = random_scalar(rng);
        let rho_v = random_scalar(rng);

        let a_x = rho_x * statement.g;
        let a_y = rho_y * statement.g;
        let a_ev = rho_v * statement.g;
        let a_v = rho_v * statement.x_g;
        let a_components = statement
            .components
            .iter()
            .map(|(key, c_s)| (*key, rho_y * *c_s))
            .collect::<BTreeMap<_, _>>();

        let mut transcript = Transcript::new(b"dkvac-subset-direct-issue-v2");
        append_subset_direct_issue_statement(&mut transcript, statement);
        append_subset_direct_issue_commitments(
            &mut transcript,
            &a_x,
            &a_y,
            &a_ev,
            &a_v,
            &a_components,
        );
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        Self {
            a_x,
            a_y,
            a_ev,
            a_v,
            a_components,
            z_x: rho_x + c * witness.x,
            z_y: rho_y + c * witness.y,
            z_v: rho_v + c * witness.v,
        }
    }

    pub fn verify(&self, statement: &SubsetDirectIssueStatement) -> bool {
        if is_identity(&statement.v_x_g) {
            return false;
        }
        if statement.components.len() != self.a_components.len() {
            return false;
        }

        let mut transcript = Transcript::new(b"dkvac-subset-direct-issue-v2");
        append_subset_direct_issue_statement(&mut transcript, statement);
        append_subset_direct_issue_commitments(
            &mut transcript,
            &self.a_x,
            &self.a_y,
            &self.a_ev,
            &self.a_v,
            &self.a_components,
        );
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        if self.z_x * statement.g != self.a_x + c * statement.x_g {
            return false;
        }
        if self.z_y * statement.g != self.a_y + c * statement.y_g {
            return false;
        }
        if self.z_v * statement.g != self.a_ev + c * statement.ev {
            return false;
        }
        if self.z_v * statement.x_g != self.a_v + c * statement.v_x_g {
            return false;
        }

        for (key, c_s) in &statement.components {
            let Some(a_c_s) = self.a_components.get(key) else {
                return false;
            };
            let Ok(s) = scalar_from_key(key) else {
                return false;
            };
            if self.z_y * *c_s != *a_c_s + c * (statement.ev - s * *c_s) {
                return false;
            }
        }

        true
    }
}

impl SubsetDelegatableIssueProof {
    pub fn prove<R: CryptoRng + RngCore>(
        rng: &mut R,
        statement: &SubsetDelegatableIssueStatement,
        witness: &SubsetDelegatableIssueWitness,
    ) -> Self {
        let rho_x = random_scalar(rng);
        let rho_y = random_scalar(rng);
        let rho_v = random_scalar(rng);
        let rho_z = random_scalar(rng);

        let a_x = rho_x * statement.g;
        let a_y = rho_y * statement.g;
        let a_ev = rho_v * statement.g;
        let a_ez = rho_z * statement.g;
        let a_e = rho_v * statement.x_g + rho_z * statement.h;
        let a_components = statement
            .components
            .iter()
            .map(|(key, c_s)| (*key, rho_y * *c_s))
            .collect::<BTreeMap<_, _>>();

        let mut transcript = Transcript::new(b"dkvac-subset-delegatable-issue-v2");
        append_subset_delegatable_issue_statement(&mut transcript, statement);
        append_subset_delegatable_issue_commitments(
            &mut transcript,
            &a_x,
            &a_y,
            &a_ev,
            &a_ez,
            &a_e,
            &a_components,
        );
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        Self {
            a_x,
            a_y,
            a_ev,
            a_ez,
            a_e,
            a_components,
            z_x: rho_x + c * witness.x,
            z_y: rho_y + c * witness.y,
            z_v: rho_v + c * witness.v,
            z_z: rho_z + c * witness.z,
        }
    }

    pub fn verify(&self, statement: &SubsetDelegatableIssueStatement) -> bool {
        if is_identity(&statement.ev) {
            return false;
        }
        if statement.components.len() != self.a_components.len() {
            return false;
        }

        let mut transcript = Transcript::new(b"dkvac-subset-delegatable-issue-v2");
        append_subset_delegatable_issue_statement(&mut transcript, statement);
        append_subset_delegatable_issue_commitments(
            &mut transcript,
            &self.a_x,
            &self.a_y,
            &self.a_ev,
            &self.a_ez,
            &self.a_e,
            &self.a_components,
        );
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        if self.z_x * statement.g != self.a_x + c * statement.x_g {
            return false;
        }
        if self.z_y * statement.g != self.a_y + c * statement.y_g {
            return false;
        }
        if self.z_v * statement.g != self.a_ev + c * statement.ev {
            return false;
        }
        if self.z_z * statement.g != self.a_ez + c * statement.ez {
            return false;
        }
        if self.z_v * statement.x_g + self.z_z * statement.h != self.a_e + c * statement.e {
            return false;
        }

        for (key, c_s) in &statement.components {
            let Some(a_c_s) = self.a_components.get(key) else {
                return false;
            };
            let Ok(s) = scalar_from_key(key) else {
                return false;
            };
            if self.z_y * *c_s != *a_c_s + c * (statement.ev - s * *c_s) {
                return false;
            }
        }

        true
    }
}

impl VectorDelegateStatement {
    /// The adjusted MAC base is derived, never supplied independently of the messages/keys.
    fn adjusted_c(&self) -> Option<Point> {
        if !is_valid_delegation(&self.old_message, &self.new_message)
            || !map_keys_match_set(
                &self.old_malleable_keys,
                &self.old_message.malleable_indices,
            )
            || !map_keys_match_set(
                &self.new_malleable_keys,
                &self.new_message.malleable_indices,
            )
        {
            return None;
        }
        Some(
            self.old_message
                .malleable_indices
                .difference(&self.new_message.malleable_indices)
                .fold(self.old_c, |acc, idx| {
                    acc + (self.new_message.attributes[*idx] - self.old_message.attributes[*idx])
                        * self.old_malleable_keys[idx]
                }),
        )
    }
}

impl VectorDelegateProof {
    pub fn prove<R: CryptoRng + RngCore>(
        rng: &mut R,
        statement: &VectorDelegateStatement,
        witness: &VectorDelegateWitness,
    ) -> Self {
        let adjusted_c = statement
            .adjusted_c()
            .expect("valid vector delegation statement");
        let rho = random_scalar(rng);
        let rho_z = random_scalar(rng);
        let a_ev = rho * statement.old_ev + rho_z * statement.h;
        let a_ez = rho * statement.old_ez + rho_z * statement.g;
        let a_c = rho * adjusted_c;
        let a_malleable_keys = statement
            .new_message
            .malleable_indices
            .iter()
            .map(|idx| (*idx, rho * statement.old_malleable_keys[idx]))
            .collect();
        let mut proof = Self {
            a_ev,
            a_ez,
            a_c,
            a_malleable_keys,
            z_mu: Scalar::ZERO,
            z_z_prime: Scalar::ZERO,
        };
        let c = proof.challenge(statement);
        proof.z_mu = rho + c * witness.mu;
        proof.z_z_prime = rho_z + c * witness.z_prime;
        proof
    }

    fn challenge(&self, statement: &VectorDelegateStatement) -> Scalar {
        let mut transcript = Transcript::new(b"dkvac-vector-delegate-v2");
        append_vector_delegate_statement(&mut transcript, statement);
        transcript_append_point(&mut transcript, b"a_ev", &self.a_ev);
        transcript_append_point(&mut transcript, b"a_ez", &self.a_ez);
        transcript_append_point(&mut transcript, b"a_c", &self.a_c);
        append_indexed_points(&mut transcript, b"a_malleable_keys", &self.a_malleable_keys);
        transcript_challenge_scalar(&mut transcript, b"c")
    }

    pub fn verify(&self, statement: &VectorDelegateStatement) -> bool {
        let Some(adjusted_c) = statement.adjusted_c() else {
            return false;
        };
        if !map_keys_match_set(
            &self.a_malleable_keys,
            &statement.new_message.malleable_indices,
        ) {
            return false;
        }
        let c = self.challenge(statement);
        self.z_mu * statement.old_ev + self.z_z_prime * statement.h
            == self.a_ev + c * statement.new_ev
            && self.z_mu * statement.old_ez + self.z_z_prime * statement.g
                == self.a_ez + c * statement.new_ez
            && self.z_mu * adjusted_c == self.a_c + c * statement.new_c
            && statement.new_message.malleable_indices.iter().all(|idx| {
                self.z_mu * statement.old_malleable_keys[idx]
                    == self.a_malleable_keys[idx] + c * statement.new_malleable_keys[idx]
            })
    }
}

impl VectorPresentationProof {
    pub fn prove<R: CryptoRng + RngCore>(
        rng: &mut R,
        statement: &VectorPresentationStatement,
        witness: &VectorPresentationWitness,
    ) -> Self {
        assert!(
            statement
                .q_hidden
                .keys()
                .all(|idx| *idx < statement.r_y_i_g.len())
        );
        let indices = statement.q_hidden.keys().copied().collect::<Vec<_>>();
        assert!(matching_hidden_index_sets(
            &statement.q_hidden,
            &witness.hidden_attributes,
            &witness.beta,
        ));

        let rho_mu_prime = random_scalar(rng);
        let mut rho_beta = BTreeMap::new();
        let mut rho_s = BTreeMap::new();

        for idx in &indices {
            rho_beta.insert(*idx, random_scalar(rng));
            rho_s.insert(*idx, random_scalar(rng));
        }

        let a_p = indices
            .iter()
            .fold(-(rho_mu_prime * statement.r_h), |acc, idx| {
                acc + rho_beta[idx] * statement.r_y_i_g[*idx]
            });
        let a_q = indices
            .iter()
            .map(|idx| {
                (
                    *idx,
                    rho_s[idx] * statement.v_prime + rho_beta[idx] * statement.g,
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut transcript = Transcript::new(b"dkvac-vector-presentation-v2");
        append_vector_presentation_statement(&mut transcript, statement);
        transcript_append_point(&mut transcript, b"a_p", &a_p);
        for (idx, point) in &a_q {
            transcript_append_usize(&mut transcript, b"a_q_idx", *idx);
            transcript_append_point(&mut transcript, b"a_q_point", point);
        }
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        let z_beta = indices
            .iter()
            .map(|idx| (*idx, rho_beta[idx] + c * witness.beta[idx]))
            .collect::<BTreeMap<_, _>>();
        let z_s = indices
            .iter()
            .map(|idx| (*idx, rho_s[idx] + c * witness.hidden_attributes[idx]))
            .collect::<BTreeMap<_, _>>();

        Self {
            a_p,
            a_q,
            z_mu_prime: rho_mu_prime + c * witness.mu_prime,
            z_beta,
            z_s,
        }
    }

    pub fn verify(&self, statement: &VectorPresentationStatement) -> bool {
        if statement
            .q_hidden
            .keys()
            .any(|idx| *idx >= statement.r_y_i_g.len())
        {
            return false;
        }
        if !matching_hidden_index_sets(&statement.q_hidden, &self.z_beta, &self.z_s) {
            return false;
        }
        if self.a_q.keys().copied().collect::<Vec<_>>()
            != statement.q_hidden.keys().copied().collect::<Vec<_>>()
        {
            return false;
        }

        let indices = statement.q_hidden.keys().copied().collect::<Vec<_>>();
        let mut transcript = Transcript::new(b"dkvac-vector-presentation-v2");
        append_vector_presentation_statement(&mut transcript, statement);
        transcript_append_point(&mut transcript, b"a_p", &self.a_p);
        for (idx, point) in &self.a_q {
            transcript_append_usize(&mut transcript, b"a_q_idx", *idx);
            transcript_append_point(&mut transcript, b"a_q_point", point);
        }
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        let lhs_p = indices
            .iter()
            .fold(-(self.z_mu_prime * statement.r_h), |acc, idx| {
                acc + self.z_beta[idx] * statement.r_y_i_g[*idx]
            });
        let rhs_p = self.a_p + c * statement.p;
        if lhs_p != rhs_p {
            return false;
        }

        for idx in indices {
            let lhs_q = self.z_s[&idx] * statement.v_prime + self.z_beta[&idx] * statement.g;
            let rhs_q = self.a_q[&idx] + c * statement.q_hidden[&idx];
            if lhs_q != rhs_q {
                return false;
            }
        }

        true
    }
}

impl VectorDirectIssueProof {
    pub fn prove<R: CryptoRng + RngCore>(
        rng: &mut R,
        statement: &VectorDirectIssueStatement,
        witness: &VectorDirectIssueWitness,
    ) -> Self {
        assert!(valid_vector_issue_indices(
            &statement.attributes,
            &statement.r_y_i_g,
            &statement.malleable_keys,
            &statement.malleable_indices,
            &witness.y_i,
        ));

        let rho_r_inv = random_scalar(rng);
        let rho_r = random_scalar(rng);
        let rho_x = random_scalar(rng);
        let rho_v = random_scalar(rng);
        let rho_y = (0..statement.attributes.len())
            .map(|idx| (idx, random_scalar(rng)))
            .collect::<BTreeMap<_, _>>();
        let d = vector_issue_d(statement.r_x_g, &statement.r_y_i_g, &statement.attributes);

        let a_v = rho_v * statement.g;
        let a_c = rho_r * statement.c - rho_v * d;
        let a_malleable_keys = statement
            .malleable_indices
            .iter()
            .map(|idx| {
                (
                    *idx,
                    rho_r * statement.malleable_keys[idx] - rho_v * statement.r_y_i_g[*idx],
                )
            })
            .collect::<BTreeMap<_, _>>();
        let a_r = rho_r * statement.h;
        let a_r_inv = rho_r_inv * statement.r_h;
        let a_x = rho_r_inv * statement.r_x_g - rho_x * statement.g;
        let a_y = rho_y
            .keys()
            .map(|idx| {
                (
                    *idx,
                    rho_r_inv * statement.r_y_i_g[*idx] - rho_y[idx] * statement.g,
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut transcript = Transcript::new(b"dkvac-vector-direct-issue-paper-v2");
        append_vector_direct_issue_statement(&mut transcript, statement);
        append_vector_direct_issue_commitments(
            &mut transcript,
            &a_v,
            &a_c,
            &a_malleable_keys,
            &a_r,
            &a_r_inv,
            &a_x,
            &a_y,
        );
        let challenge = transcript_challenge_scalar(&mut transcript, b"c");

        Self {
            a_v,
            a_c,
            a_malleable_keys,
            a_r,
            a_r_inv,
            a_x,
            a_y,
            z_r_inv: rho_r_inv + challenge * witness.r_inv,
            z_r: rho_r + challenge * witness.r,
            z_x: rho_x + challenge * witness.x,
            z_y: rho_y
                .keys()
                .map(|idx| (*idx, rho_y[idx] + challenge * witness.y_i[idx]))
                .collect(),
            z_v: rho_v + challenge * witness.v,
        }
    }

    pub fn verify(&self, statement: &VectorDirectIssueStatement) -> bool {
        if is_identity(&statement.v_g) {
            return false;
        }
        if !valid_vector_issue_proof_indices(
            &statement.attributes,
            &statement.r_y_i_g,
            &statement.malleable_keys,
            &statement.malleable_indices,
            &self.a_malleable_keys,
            &self.a_y,
            &self.z_y,
        ) {
            return false;
        }

        let mut transcript = Transcript::new(b"dkvac-vector-direct-issue-paper-v2");
        append_vector_direct_issue_statement(&mut transcript, statement);
        append_vector_direct_issue_commitments(
            &mut transcript,
            &self.a_v,
            &self.a_c,
            &self.a_malleable_keys,
            &self.a_r,
            &self.a_r_inv,
            &self.a_x,
            &self.a_y,
        );
        let challenge = transcript_challenge_scalar(&mut transcript, b"c");
        let d = vector_issue_d(statement.r_x_g, &statement.r_y_i_g, &statement.attributes);

        if self.z_v * statement.g != self.a_v + challenge * statement.v_g
            || self.z_r * statement.c - self.z_v * d != self.a_c
            || self.z_r * statement.h != self.a_r + challenge * statement.r_h
            || self.z_r_inv * statement.r_h != self.a_r_inv + challenge * statement.h
            || self.z_r_inv * statement.r_x_g - self.z_x * statement.g != self.a_x
        {
            return false;
        }

        for idx in &statement.malleable_indices {
            if self.z_r * statement.malleable_keys[idx] - self.z_v * statement.r_y_i_g[*idx]
                != self.a_malleable_keys[idx]
            {
                return false;
            }
        }

        for idx in 0..statement.attributes.len() {
            if self.z_r_inv * statement.r_y_i_g[idx] - self.z_y[&idx] * statement.g
                != self.a_y[&idx]
            {
                return false;
            }
        }
        true
    }
}

impl VectorDelegatableIssueProof {
    pub fn prove<R: CryptoRng + RngCore>(
        rng: &mut R,
        statement: &VectorDelegatableIssueStatement,
        witness: &VectorDelegatableIssueWitness,
    ) -> Self {
        assert!(valid_vector_issue_indices(
            &statement.attributes,
            &statement.r_y_i_g,
            &statement.malleable_keys,
            &statement.malleable_indices,
            &witness.y_i,
        ));

        let rho_r_inv = random_scalar(rng);
        let rho_r = random_scalar(rng);
        let rho_x = random_scalar(rng);
        let rho_v = random_scalar(rng);
        let rho_z = random_scalar(rng);
        let rho_y = (0..statement.attributes.len())
            .map(|idx| (idx, random_scalar(rng)))
            .collect::<BTreeMap<_, _>>();
        let d = vector_issue_d(statement.r_x_g, &statement.r_y_i_g, &statement.attributes);

        let a_ev = rho_v * statement.g + rho_z * statement.h;
        let a_ez = rho_z * statement.g;
        let a_c = rho_r * statement.c - rho_v * d;
        let a_malleable_keys = statement
            .malleable_indices
            .iter()
            .map(|idx| {
                (
                    *idx,
                    rho_r * statement.malleable_keys[idx] - rho_v * statement.r_y_i_g[*idx],
                )
            })
            .collect::<BTreeMap<_, _>>();
        let a_r = rho_r * statement.h;
        let a_r_inv = rho_r_inv * statement.r_h;
        let a_x = rho_r_inv * statement.r_x_g - rho_x * statement.g;
        let a_y = rho_y
            .keys()
            .map(|idx| {
                (
                    *idx,
                    rho_r_inv * statement.r_y_i_g[*idx] - rho_y[idx] * statement.g,
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut transcript = Transcript::new(b"dkvac-vector-delegatable-issue-paper-v2");
        append_vector_delegatable_issue_statement(&mut transcript, statement);
        append_vector_delegatable_issue_commitments(
            &mut transcript,
            &a_ev,
            &a_ez,
            &a_c,
            &a_malleable_keys,
            &a_r,
            &a_r_inv,
            &a_x,
            &a_y,
        );
        let challenge = transcript_challenge_scalar(&mut transcript, b"c");

        Self {
            a_ev,
            a_ez,
            a_c,
            a_malleable_keys,
            a_r,
            a_r_inv,
            a_x,
            a_y,
            z_r_inv: rho_r_inv + challenge * witness.r_inv,
            z_r: rho_r + challenge * witness.r,
            z_x: rho_x + challenge * witness.x,
            z_y: rho_y
                .keys()
                .map(|idx| (*idx, rho_y[idx] + challenge * witness.y_i[idx]))
                .collect(),
            z_v: rho_v + challenge * witness.v,
            z_z: rho_z + challenge * witness.z,
        }
    }

    pub fn verify(&self, statement: &VectorDelegatableIssueStatement) -> bool {
        if !valid_vector_issue_proof_indices(
            &statement.attributes,
            &statement.r_y_i_g,
            &statement.malleable_keys,
            &statement.malleable_indices,
            &self.a_malleable_keys,
            &self.a_y,
            &self.z_y,
        ) {
            return false;
        }

        let mut transcript = Transcript::new(b"dkvac-vector-delegatable-issue-paper-v2");
        append_vector_delegatable_issue_statement(&mut transcript, statement);
        append_vector_delegatable_issue_commitments(
            &mut transcript,
            &self.a_ev,
            &self.a_ez,
            &self.a_c,
            &self.a_malleable_keys,
            &self.a_r,
            &self.a_r_inv,
            &self.a_x,
            &self.a_y,
        );
        let challenge = transcript_challenge_scalar(&mut transcript, b"c");
        let d = vector_issue_d(statement.r_x_g, &statement.r_y_i_g, &statement.attributes);

        if self.z_v * statement.g + self.z_z * statement.h != self.a_ev + challenge * statement.ev
            || self.z_z * statement.g != self.a_ez + challenge * statement.ez
            || self.z_r * statement.c - self.z_v * d != self.a_c
            || self.z_r * statement.h != self.a_r + challenge * statement.r_h
            || self.z_r_inv * statement.r_h != self.a_r_inv + challenge * statement.h
            || self.z_r_inv * statement.r_x_g - self.z_x * statement.g != self.a_x
        {
            return false;
        }

        for idx in &statement.malleable_indices {
            if self.z_r * statement.malleable_keys[idx] - self.z_v * statement.r_y_i_g[*idx]
                != self.a_malleable_keys[idx]
            {
                return false;
            }
        }

        for idx in 0..statement.attributes.len() {
            if self.z_r_inv * statement.r_y_i_g[idx] - self.z_y[&idx] * statement.g
                != self.a_y[&idx]
            {
                return false;
            }
        }
        true
    }
}

impl Default for VectorIssueProofPlaceholder {
    fn default() -> Self {
        Self::new()
    }
}

impl VectorIssueProofPlaceholder {
    pub fn new() -> Self {
        Self {
            warning: "WARNING: legacy placeholder: verification is not implemented by this type. Active vector issuance uses exact Schnorr proofs.".to_string(),
        }
    }

    pub fn verify(&self) -> bool {
        // Legacy test-only scaffold; not called by the active protocol.
        true
    }
}

impl Default for VectorIssuePaperProofPlaceholder {
    fn default() -> Self {
        Self::new()
    }
}

impl VectorIssuePaperProofPlaceholder {
    pub fn new() -> Self {
        Self {
            warning: "WARNING: legacy rel_veciss placeholder; it verifies nothing. Active issuance uses VectorDirectIssueProof and VectorDelegatableIssueProof. Do not use this placeholder for security claims.".to_string(),
        }
    }

    pub fn verify(&self) -> bool {
        // WARNING: legacy placeholder, not used by either active protocol.
        // Do not use this placeholder for security claims.
        true
    }
}

impl VectorIssueOption3Proof {
    pub fn prove<R: CryptoRng + RngCore>(
        rng: &mut R,
        statement: &VectorIssueOption3Statement,
        witness: &VectorIssueOption3Witness,
    ) -> Self {
        assert_eq!(statement.attributes.len(), statement.y_i_g.len());
        assert_eq!(statement.attributes.len(), statement.y_power_points.len());

        let rho_x = random_scalar(rng);
        let rho_v = random_scalar(rng);
        let a_x = rho_x * statement.g;
        let a_v = rho_v * statement.g;
        let a_c = rho_x * statement.v_g
            + statement
                .attributes
                .iter()
                .enumerate()
                .fold(Point::default(), |acc, (idx, attribute)| {
                    acc + *attribute * (rho_v * statement.y_i_g[idx])
                });
        let a_y_power_points = statement
            .y_i_g
            .iter()
            .map(|y_i| rho_v * *y_i)
            .collect::<Vec<_>>();

        let mut transcript = Transcript::new(b"dkvac-vector-issue-option3-v1");
        append_vector_issue_option3_statement(&mut transcript, statement);
        append_vector_issue_option3_commitments(
            &mut transcript,
            &a_x,
            &a_v,
            &a_c,
            &a_y_power_points,
        );
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        Self {
            a_x,
            a_v,
            a_c,
            a_y_power_points,
            z_x: rho_x + c * witness.x,
            z_v: rho_v + c * witness.v,
        }
    }

    pub fn verify(&self, statement: &VectorIssueOption3Statement) -> bool {
        if statement.attributes.len() != statement.y_i_g.len()
            || statement.attributes.len() != statement.y_power_points.len()
            || statement.attributes.len() != self.a_y_power_points.len()
        {
            return false;
        }

        let mut transcript = Transcript::new(b"dkvac-vector-issue-option3-v1");
        append_vector_issue_option3_statement(&mut transcript, statement);
        append_vector_issue_option3_commitments(
            &mut transcript,
            &self.a_x,
            &self.a_v,
            &self.a_c,
            &self.a_y_power_points,
        );
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        if self.z_x * statement.g != self.a_x + c * statement.x_g {
            return false;
        }
        if self.z_v * statement.g != self.a_v + c * statement.v_g {
            return false;
        }

        let lhs_c = self.z_x * statement.v_g
            + statement
                .attributes
                .iter()
                .enumerate()
                .fold(Point::default(), |acc, (idx, attribute)| {
                    acc + *attribute * (self.z_v * statement.y_i_g[idx])
                });
        if lhs_c != self.a_c + c * statement.c {
            return false;
        }

        for idx in 0..statement.y_i_g.len() {
            if self.z_v * statement.y_i_g[idx]
                != self.a_y_power_points[idx] + c * statement.y_power_points[idx]
            {
                return false;
            }
        }

        true
    }
}

fn append_subset_delegate_statement(
    transcript: &mut Transcript,
    statement: &SubsetDelegateStatement,
) {
    transcript_append_point(transcript, b"g", &statement.g);
    transcript_append_point(transcript, b"h", &statement.h);
    transcript_append_usize(
        transcript,
        b"old_components_len",
        statement.old_components.len(),
    );
    transcript_append_point(transcript, b"old_e", &statement.old_e);
    transcript_append_point(transcript, b"old_ev", &statement.old_ev);
    transcript_append_point(transcript, b"old_ez", &statement.old_ez);
    for (key, point) in &statement.old_components {
        transcript.append_message(b"old_component_key", &key.0);
        transcript_append_point(transcript, b"old_component_value", point);
    }
    transcript_append_point(transcript, b"new_e", &statement.new_e);
    transcript_append_point(transcript, b"new_ev", &statement.new_ev);
    transcript_append_point(transcript, b"new_ez", &statement.new_ez);
    transcript_append_usize(
        transcript,
        b"new_components_len",
        statement.new_components.len(),
    );
    for (key, point) in &statement.new_components {
        transcript.append_message(b"new_component_key", &key.0);
        transcript_append_point(transcript, b"new_component_value", point);
    }
}

fn append_subset_direct_issue_statement(
    transcript: &mut Transcript,
    statement: &SubsetDirectIssueStatement,
) {
    transcript_append_point(transcript, b"g", &statement.g);
    transcript_append_point(transcript, b"x_g", &statement.x_g);
    transcript_append_point(transcript, b"y_g", &statement.y_g);
    transcript_append_point(transcript, b"v_x_g", &statement.v_x_g);
    transcript_append_point(transcript, b"ev", &statement.ev);
    transcript_append_usize(transcript, b"components_len", statement.components.len());
    for (key, point) in &statement.components {
        transcript.append_message(b"component_key", &key.0);
        transcript_append_point(transcript, b"component_value", point);
    }
}

fn append_subset_direct_issue_commitments(
    transcript: &mut Transcript,
    a_x: &Point,
    a_y: &Point,
    a_ev: &Point,
    a_v: &Point,
    a_components: &BTreeMap<ScalarBytes, Point>,
) {
    transcript_append_point(transcript, b"a_x", a_x);
    transcript_append_point(transcript, b"a_y", a_y);
    transcript_append_point(transcript, b"a_ev", a_ev);
    transcript_append_point(transcript, b"a_v", a_v);
    for (key, point) in a_components {
        transcript.append_message(b"a_component_key", &key.0);
        transcript_append_point(transcript, b"a_component_value", point);
    }
}

fn append_subset_delegatable_issue_statement(
    transcript: &mut Transcript,
    statement: &SubsetDelegatableIssueStatement,
) {
    transcript_append_point(transcript, b"g", &statement.g);
    transcript_append_point(transcript, b"h", &statement.h);
    transcript_append_point(transcript, b"x_g", &statement.x_g);
    transcript_append_point(transcript, b"y_g", &statement.y_g);
    transcript_append_point(transcript, b"e", &statement.e);
    transcript_append_point(transcript, b"ev", &statement.ev);
    transcript_append_point(transcript, b"ez", &statement.ez);
    transcript_append_usize(transcript, b"components_len", statement.components.len());
    for (key, point) in &statement.components {
        transcript.append_message(b"component_key", &key.0);
        transcript_append_point(transcript, b"component_value", point);
    }
}

fn append_subset_delegatable_issue_commitments(
    transcript: &mut Transcript,
    a_x: &Point,
    a_y: &Point,
    a_ev: &Point,
    a_ez: &Point,
    a_e: &Point,
    a_components: &BTreeMap<ScalarBytes, Point>,
) {
    transcript_append_point(transcript, b"a_x", a_x);
    transcript_append_point(transcript, b"a_y", a_y);
    transcript_append_point(transcript, b"a_ev", a_ev);
    transcript_append_point(transcript, b"a_ez", a_ez);
    transcript_append_point(transcript, b"a_e", a_e);
    for (key, point) in a_components {
        transcript.append_message(b"a_component_key", &key.0);
        transcript_append_point(transcript, b"a_component_value", point);
    }
}

fn append_indexed_points(
    transcript: &mut Transcript,
    label: &'static [u8],
    points: &BTreeMap<usize, Point>,
) {
    transcript_append_usize(transcript, label, points.len());
    for (idx, point) in points {
        transcript_append_usize(transcript, b"index", *idx);
        transcript_append_point(transcript, b"point", point);
    }
}

fn append_message(transcript: &mut Transcript, label: &'static [u8], message: &Message) {
    transcript_append_usize(transcript, label, message.attributes.len());
    for value in &message.attributes {
        transcript_append_scalar(transcript, b"attribute", value);
    }
    transcript_append_usize(
        transcript,
        b"malleable_len",
        message.malleable_indices.len(),
    );
    for idx in &message.malleable_indices {
        transcript_append_usize(transcript, b"malleable_idx", *idx);
    }
}

fn append_vector_delegate_statement(
    transcript: &mut Transcript,
    statement: &VectorDelegateStatement,
) {
    transcript_append_point(transcript, b"g", &statement.g);
    transcript_append_point(transcript, b"h", &statement.h);
    transcript_append_point(transcript, b"old_ev", &statement.old_ev);
    transcript_append_point(transcript, b"old_ez", &statement.old_ez);
    transcript_append_point(transcript, b"old_c", &statement.old_c);
    transcript_append_point(transcript, b"new_ev", &statement.new_ev);
    transcript_append_point(transcript, b"new_ez", &statement.new_ez);
    transcript_append_point(transcript, b"new_c", &statement.new_c);
    append_message(transcript, b"old_message", &statement.old_message);
    append_message(transcript, b"new_message", &statement.new_message);
    append_indexed_points(
        transcript,
        b"old_malleable_keys",
        &statement.old_malleable_keys,
    );
    append_indexed_points(
        transcript,
        b"new_malleable_keys",
        &statement.new_malleable_keys,
    );
}

fn append_vector_presentation_statement(
    transcript: &mut Transcript,
    statement: &VectorPresentationStatement,
) {
    transcript_append_point(transcript, b"g", &statement.g);
    transcript_append_point(transcript, b"h", &statement.h);
    transcript_append_point(transcript, b"r_h", &statement.r_h);
    transcript_append_point(transcript, b"r_x_g", &statement.r_x_g);
    transcript_append_usize(transcript, b"r_y_i_len", statement.r_y_i_g.len());
    for point in &statement.r_y_i_g {
        transcript_append_point(transcript, b"r_y_i_g", point);
    }
    transcript_append_point(transcript, b"v_prime", &statement.v_prime);
    transcript_append_point(transcript, b"p", &statement.p);
    append_indexed_points(transcript, b"q_hidden", &statement.q_hidden);
}

fn append_vector_direct_issue_statement(
    transcript: &mut Transcript,
    statement: &VectorDirectIssueStatement,
) {
    transcript_append_point(transcript, b"g", &statement.g);
    transcript_append_point(transcript, b"h", &statement.h);
    transcript_append_point(transcript, b"r_h", &statement.r_h);
    transcript_append_point(transcript, b"r_x_g", &statement.r_x_g);
    append_vector_issue_common_statement(
        transcript,
        &statement.r_y_i_g,
        &statement.attributes,
        &statement.malleable_keys,
        &statement.malleable_indices,
    );
    transcript_append_point(transcript, b"v_g", &statement.v_g);
    transcript_append_point(transcript, b"issue_c", &statement.c);
}

fn append_vector_delegatable_issue_statement(
    transcript: &mut Transcript,
    statement: &VectorDelegatableIssueStatement,
) {
    transcript_append_point(transcript, b"g", &statement.g);
    transcript_append_point(transcript, b"h", &statement.h);
    transcript_append_point(transcript, b"r_h", &statement.r_h);
    transcript_append_point(transcript, b"r_x_g", &statement.r_x_g);
    append_vector_issue_common_statement(
        transcript,
        &statement.r_y_i_g,
        &statement.attributes,
        &statement.malleable_keys,
        &statement.malleable_indices,
    );
    transcript_append_point(transcript, b"ev", &statement.ev);
    transcript_append_point(transcript, b"ez", &statement.ez);
    transcript_append_point(transcript, b"issue_c", &statement.c);
}

fn append_vector_issue_common_statement(
    transcript: &mut Transcript,
    r_y_i_g: &[Point],
    attributes: &[Scalar],
    malleable_keys: &BTreeMap<usize, Point>,
    malleable_indices: &BTreeSet<usize>,
) {
    transcript_append_usize(transcript, b"r_y_i_len", r_y_i_g.len());
    transcript_append_usize(transcript, b"attributes_len", attributes.len());
    transcript_append_usize(transcript, b"malleable_len", malleable_indices.len());
    transcript_append_usize(transcript, b"malleable_keys_len", malleable_keys.len());
    for (idx, point) in r_y_i_g.iter().enumerate() {
        transcript_append_usize(transcript, b"r_y_i_idx", idx);
        transcript_append_point(transcript, b"r_y_i_g", point);
    }
    for (idx, attribute) in attributes.iter().enumerate() {
        transcript_append_usize(transcript, b"attribute_idx", idx);
        transcript_append_scalar(transcript, b"attribute", attribute);
    }
    for idx in malleable_indices {
        transcript_append_usize(transcript, b"malleable_idx", *idx);
    }
    for (idx, point) in malleable_keys {
        transcript_append_usize(transcript, b"malleable_key_idx", *idx);
        transcript_append_point(transcript, b"malleable_key", point);
    }
}

// Keep the named mathematical commitments explicit at both prover and verifier.
#[allow(clippy::too_many_arguments)]
fn append_vector_direct_issue_commitments(
    transcript: &mut Transcript,
    a_v: &Point,
    a_c: &Point,
    a_malleable_keys: &BTreeMap<usize, Point>,
    a_r: &Point,
    a_r_inv: &Point,
    a_x: &Point,
    a_y: &BTreeMap<usize, Point>,
) {
    transcript_append_point(transcript, b"a_v", a_v);
    append_vector_issue_common_commitments(
        transcript,
        a_c,
        a_malleable_keys,
        a_r,
        a_r_inv,
        a_x,
        a_y,
    );
}

#[allow(clippy::too_many_arguments)]
fn append_vector_delegatable_issue_commitments(
    transcript: &mut Transcript,
    a_ev: &Point,
    a_ez: &Point,
    a_c: &Point,
    a_malleable_keys: &BTreeMap<usize, Point>,
    a_r: &Point,
    a_r_inv: &Point,
    a_x: &Point,
    a_y: &BTreeMap<usize, Point>,
) {
    transcript_append_point(transcript, b"a_ev", a_ev);
    transcript_append_point(transcript, b"a_ez", a_ez);
    append_vector_issue_common_commitments(
        transcript,
        a_c,
        a_malleable_keys,
        a_r,
        a_r_inv,
        a_x,
        a_y,
    );
}

fn append_vector_issue_common_commitments(
    transcript: &mut Transcript,
    a_c: &Point,
    a_malleable_keys: &BTreeMap<usize, Point>,
    a_r: &Point,
    a_r_inv: &Point,
    a_x: &Point,
    a_y: &BTreeMap<usize, Point>,
) {
    transcript_append_point(transcript, b"a_c", a_c);
    for (idx, point) in a_malleable_keys {
        transcript_append_usize(transcript, b"a_malleable_key_idx", *idx);
        transcript_append_point(transcript, b"a_malleable_key", point);
    }
    transcript_append_point(transcript, b"a_r", a_r);
    transcript_append_point(transcript, b"a_r_inv", a_r_inv);
    transcript_append_point(transcript, b"a_x", a_x);
    for (idx, point) in a_y {
        transcript_append_usize(transcript, b"a_y_idx", *idx);
        transcript_append_point(transcript, b"a_y", point);
    }
}

fn append_vector_issue_option3_statement(
    transcript: &mut Transcript,
    statement: &VectorIssueOption3Statement,
) {
    transcript_append_point(transcript, b"g", &statement.g);
    transcript_append_point(transcript, b"x_g", &statement.x_g);
    transcript_append_point(transcript, b"v_g", &statement.v_g);
    transcript_append_point(transcript, b"c", &statement.c);
    for (idx, y_i_g) in statement.y_i_g.iter().enumerate() {
        transcript_append_usize(transcript, b"y_i_idx", idx);
        transcript_append_point(transcript, b"y_i_point", y_i_g);
    }
    for (idx, attribute) in statement.attributes.iter().enumerate() {
        transcript_append_usize(transcript, b"attribute_idx", idx);
        transcript_append_scalar(transcript, b"attribute_value", attribute);
    }
    for (idx, point) in statement.y_power_points.iter().enumerate() {
        transcript_append_usize(transcript, b"m_i_idx", idx);
        transcript_append_point(transcript, b"m_i_point", point);
    }
}

fn append_vector_issue_option3_commitments(
    transcript: &mut Transcript,
    a_x: &Point,
    a_v: &Point,
    a_c: &Point,
    a_y_power_points: &[Point],
) {
    transcript_append_point(transcript, b"a_x", a_x);
    transcript_append_point(transcript, b"a_v", a_v);
    transcript_append_point(transcript, b"a_c", a_c);
    for (idx, point) in a_y_power_points.iter().enumerate() {
        transcript_append_usize(transcript, b"a_m_i_idx", idx);
        transcript_append_point(transcript, b"a_m_i_point", point);
    }
}

fn matching_hidden_index_sets<U, V, W>(
    q_hidden: &BTreeMap<usize, U>,
    hidden_attributes: &BTreeMap<usize, V>,
    beta: &BTreeMap<usize, W>,
) -> bool {
    let q_keys = q_hidden.keys().copied().collect::<Vec<_>>();
    let s_keys = hidden_attributes.keys().copied().collect::<Vec<_>>();
    let b_keys = beta.keys().copied().collect::<Vec<_>>();
    q_keys == s_keys && s_keys == b_keys
}

fn valid_vector_issue_indices<T>(
    attributes: &[Scalar],
    r_y_i_g: &[Point],
    malleable_keys: &BTreeMap<usize, Point>,
    malleable_indices: &BTreeSet<usize>,
    y_i: &BTreeMap<usize, T>,
) -> bool {
    attributes.len() == r_y_i_g.len()
        && malleable_indices.iter().all(|idx| *idx < attributes.len())
        && map_keys_match_set(malleable_keys, malleable_indices)
        && y_i.keys().copied().eq(0..attributes.len())
}

fn valid_vector_issue_proof_indices<T, U, V>(
    attributes: &[Scalar],
    r_y_i_g: &[Point],
    malleable_keys: &BTreeMap<usize, Point>,
    malleable_indices: &BTreeSet<usize>,
    a_malleable_keys: &BTreeMap<usize, T>,
    a_y: &BTreeMap<usize, U>,
    z_y: &BTreeMap<usize, V>,
) -> bool {
    attributes.len() == r_y_i_g.len()
        && malleable_indices.iter().all(|idx| *idx < attributes.len())
        && map_keys_match_set(malleable_keys, malleable_indices)
        && map_keys_match_set(a_malleable_keys, malleable_indices)
        && a_y.keys().copied().eq(0..attributes.len())
        && z_y.keys().copied().eq(0..attributes.len())
}

fn map_keys_match_set<T>(map: &BTreeMap<usize, T>, indices: &BTreeSet<usize>) -> bool {
    map.keys().copied().eq(indices.iter().copied())
}

fn vector_issue_d(r_x_g: Point, r_y_i_g: &[Point], attributes: &[Scalar]) -> Point {
    r_y_i_g
        .iter()
        .zip(attributes)
        .fold(r_x_g, |acc, (y_i, attribute)| acc + attribute * y_i)
}

fn scalar_from_key(key: &ScalarBytes) -> Result<Scalar, ()> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(key.0)).ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::generator;
    use curve25519_dalek::traits::Identity;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn scalar(n: u64) -> Scalar {
        Scalar::from(n)
    }

    fn point(n: u64) -> Point {
        scalar(n) * generator()
    }

    fn key(n: u64) -> ScalarBytes {
        ScalarBytes(scalar(n).to_bytes())
    }

    #[test]
    fn subset_delegation_proof_accepts_valid_scaling_relation() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let mu = scalar(7);
        let old_components = BTreeMap::from([(key(1), point(11)), (key(2), point(13))]);
        let new_components = old_components
            .iter()
            .map(|(k, v)| (*k, mu * *v))
            .collect::<BTreeMap<_, _>>();
        let statement = SubsetDelegateStatement {
            g: generator(),
            h: point(17),
            old_e: point(2),
            old_ev: point(3),
            old_ez: point(5),
            old_components,
            new_e: mu * point(2),
            new_ev: mu * point(3),
            new_ez: mu * point(5),
            new_components,
        };
        let witness = SubsetDelegateWitness {
            mu,
            z_prime: Scalar::ZERO,
        };
        let proof = SubsetDelegateProof::prove(&mut rng, &statement, &witness);
        assert!(proof.verify(&statement));
    }

    #[test]
    fn subset_delegation_proof_rejects_modified_new_component() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let mu = scalar(7);
        let old_components = BTreeMap::from([(key(1), point(11)), (key(2), point(13))]);
        let mut new_components = old_components
            .iter()
            .map(|(k, v)| (*k, mu * *v))
            .collect::<BTreeMap<_, _>>();
        new_components.insert(key(2), new_components[&key(2)] + point(1));
        let statement = SubsetDelegateStatement {
            g: generator(),
            h: point(17),
            old_e: point(2),
            old_ev: point(3),
            old_ez: point(5),
            old_components,
            new_e: mu * point(2),
            new_ev: mu * point(3),
            new_ez: mu * point(5),
            new_components,
        };
        let proof = SubsetDelegateProof::prove(
            &mut rng,
            &SubsetDelegateStatement {
                g: generator(),
                h: point(17),
                old_e: statement.old_e,
                old_ev: statement.old_ev,
                old_ez: statement.old_ez,
                old_components: statement.old_components.clone(),
                new_e: statement.new_e,
                new_ev: statement.new_ev,
                new_ez: statement.new_ez,
                new_components: statement
                    .old_components
                    .iter()
                    .map(|(k, v)| (*k, mu * *v))
                    .collect(),
            },
            &SubsetDelegateWitness {
                mu,
                z_prime: Scalar::ZERO,
            },
        );
        assert!(!proof.verify(&statement));
    }

    #[test]
    fn vector_delegation_proof_accepts_valid_scaling_relation() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let mu = scalar(9);
        let statement = VectorDelegateStatement {
            old_ev: point(4),
            old_ez: point(6),
            old_c: point(8),
            g: generator(),
            h: point(17),
            old_message: Message {
                attributes: vec![scalar(1)],
                malleable_indices: BTreeSet::new(),
            },
            new_message: Message {
                attributes: vec![scalar(1)],
                malleable_indices: BTreeSet::new(),
            },
            old_malleable_keys: BTreeMap::new(),
            new_malleable_keys: BTreeMap::new(),
            new_ev: mu * point(4),
            new_ez: mu * point(6),
            new_c: mu * point(8),
        };
        let proof = VectorDelegateProof::prove(
            &mut rng,
            &statement,
            &VectorDelegateWitness {
                mu,
                z_prime: Scalar::ZERO,
            },
        );
        assert!(proof.verify(&statement));
    }

    #[test]
    fn vector_delegation_proof_rejects_modified_new_c() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let mu = scalar(9);
        let valid_statement = VectorDelegateStatement {
            old_ev: point(4),
            old_ez: point(6),
            old_c: point(8),
            g: generator(),
            h: point(17),
            old_message: Message {
                attributes: vec![scalar(1)],
                malleable_indices: BTreeSet::new(),
            },
            new_message: Message {
                attributes: vec![scalar(1)],
                malleable_indices: BTreeSet::new(),
            },
            old_malleable_keys: BTreeMap::new(),
            new_malleable_keys: BTreeMap::new(),
            new_ev: mu * point(4),
            new_ez: mu * point(6),
            new_c: mu * point(8),
        };
        let proof = VectorDelegateProof::prove(
            &mut rng,
            &valid_statement,
            &VectorDelegateWitness {
                mu,
                z_prime: Scalar::ZERO,
            },
        );
        let bad_statement = VectorDelegateStatement {
            new_c: valid_statement.new_c + point(1),
            ..valid_statement
        };
        assert!(!proof.verify(&bad_statement));
    }

    #[test]
    fn transcript_helpers_append_values() {
        let mut transcript = Transcript::new(b"helpers");
        transcript_append_point(&mut transcript, b"p", &Point::identity());
        transcript_append_scalar(&mut transcript, b"s", &scalar(3));
        transcript_append_usize(&mut transcript, b"i", 7);
        let challenge = transcript_challenge_scalar(&mut transcript, b"c");
        assert_ne!(challenge, Scalar::ZERO);
    }

    fn subset_direct_issue_fixture() -> (SubsetDirectIssueStatement, SubsetDirectIssueWitness) {
        let g = generator();
        let x = scalar(5);
        let y = scalar(7);
        let v = scalar(11);
        let x_g = x * g;
        let y_g = y * g;
        let ev = v * g;
        let v_x_g = v * x_g;
        let components = [scalar(2), scalar(4)]
            .into_iter()
            .map(|s| {
                let c_s = (y + s).invert() * ev;
                (ScalarBytes(s.to_bytes()), c_s)
            })
            .collect::<BTreeMap<_, _>>();

        (
            SubsetDirectIssueStatement {
                g,
                x_g,
                y_g,
                v_x_g,
                ev,
                components,
            },
            SubsetDirectIssueWitness { x, y, v },
        )
    }

    fn subset_delegatable_issue_fixture() -> (
        SubsetDelegatableIssueStatement,
        SubsetDelegatableIssueWitness,
    ) {
        let g = generator();
        let h = point(17);
        let x = scalar(5);
        let y = scalar(7);
        let v = scalar(11);
        let z = scalar(13);
        let x_g = x * g;
        let y_g = y * g;
        let ev = v * g;
        let ez = z * g;
        let e = v * x_g + z * h;
        let components = [scalar(2), scalar(4)]
            .into_iter()
            .map(|s| {
                let c_s = (y + s).invert() * ev;
                (ScalarBytes(s.to_bytes()), c_s)
            })
            .collect::<BTreeMap<_, _>>();

        (
            SubsetDelegatableIssueStatement {
                g,
                h,
                x_g,
                y_g,
                e,
                ev,
                ez,
                components,
            },
            SubsetDelegatableIssueWitness { x, y, v, z },
        )
    }

    #[test]
    fn subset_direct_issue_proof_accepts_valid_statement() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let (statement, witness) = subset_direct_issue_fixture();
        let proof = SubsetDirectIssueProof::prove(&mut rng, &statement, &witness);
        assert!(proof.verify(&statement));
    }

    #[test]
    fn subset_direct_issue_proof_rejects_modified_v_x_g() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let (statement, witness) = subset_direct_issue_fixture();
        let proof = SubsetDirectIssueProof::prove(&mut rng, &statement, &witness);
        let bad_statement = SubsetDirectIssueStatement {
            v_x_g: statement.v_x_g + point(1),
            ..statement
        };
        assert!(!proof.verify(&bad_statement));
    }

    #[test]
    fn subset_direct_issue_proof_rejects_modified_component() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let (statement, witness) = subset_direct_issue_fixture();
        let proof = SubsetDirectIssueProof::prove(&mut rng, &statement, &witness);
        let mut bad_statement = statement.clone();
        let target = ScalarBytes(scalar(2).to_bytes());
        *bad_statement
            .components
            .get_mut(&target)
            .expect("component") += point(1);
        assert!(!proof.verify(&bad_statement));
    }

    #[test]
    fn subset_delegatable_issue_proof_accepts_valid_statement() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let (statement, witness) = subset_delegatable_issue_fixture();
        let proof = SubsetDelegatableIssueProof::prove(&mut rng, &statement, &witness);
        assert!(proof.verify(&statement));
    }

    #[test]
    fn subset_delegatable_issue_proof_rejects_modified_e() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let (statement, witness) = subset_delegatable_issue_fixture();
        let proof = SubsetDelegatableIssueProof::prove(&mut rng, &statement, &witness);
        let bad_statement = SubsetDelegatableIssueStatement {
            e: statement.e + point(1),
            ..statement
        };
        assert!(!proof.verify(&bad_statement));
    }

    #[test]
    fn subset_delegatable_issue_proof_rejects_modified_component() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let (statement, witness) = subset_delegatable_issue_fixture();
        let proof = SubsetDelegatableIssueProof::prove(&mut rng, &statement, &witness);
        let mut bad_statement = statement.clone();
        let target = ScalarBytes(scalar(4).to_bytes());
        *bad_statement
            .components
            .get_mut(&target)
            .expect("component") += point(1);
        assert!(!proof.verify(&bad_statement));
    }

    fn vector_presentation_fixture() -> (VectorPresentationStatement, VectorPresentationWitness) {
        let r_h = point(5);
        let v_prime = point(7);
        let hidden_attributes = BTreeMap::from([(1usize, scalar(11)), (3usize, scalar(13))]);
        let beta = BTreeMap::from([(1usize, scalar(17)), (3usize, scalar(19))]);
        let y_i_points = BTreeMap::from([(1usize, point(23)), (3usize, point(29))]);
        let q_hidden = hidden_attributes
            .iter()
            .map(|(idx, s_i)| (*idx, *s_i * v_prime + beta[idx] * generator()))
            .collect::<BTreeMap<_, _>>();
        let p = y_i_points
            .iter()
            .fold(-(scalar(31) * r_h), |acc, (idx, y_i)| {
                acc + beta[idx] * *y_i
            });
        (
            VectorPresentationStatement {
                g: generator(),
                h: point(17),
                r_x_g: point(31),
                r_h,
                r_y_i_g: vec![point(2), point(23), point(3), point(29)],
                v_prime,
                p,
                q_hidden,
            },
            VectorPresentationWitness {
                mu_prime: scalar(31),
                hidden_attributes,
                beta,
            },
        )
    }

    #[test]
    fn vector_presentation_proof_accepts_valid_statement() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let (statement, witness) = vector_presentation_fixture();
        let proof = VectorPresentationProof::prove(&mut rng, &statement, &witness);
        assert!(proof.verify(&statement));
    }

    #[test]
    fn vector_presentation_proof_rejects_wrong_hidden_attribute() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let (statement, mut witness) = vector_presentation_fixture();
        witness.hidden_attributes.insert(1, scalar(99));
        let proof = VectorPresentationProof::prove(
            &mut rng,
            &vector_presentation_fixture().0,
            &vector_presentation_fixture().1,
        );
        assert!(
            !proof.verify(&VectorPresentationStatement {
                q_hidden: statement
                    .q_hidden
                    .iter()
                    .map(|(idx, point)| {
                        if *idx == 1 {
                            (
                                *idx,
                                witness.hidden_attributes[idx] * statement.v_prime
                                    + witness.beta[idx] * generator(),
                            )
                        } else {
                            (*idx, *point)
                        }
                    })
                    .collect(),
                ..statement
            })
        );
    }

    #[test]
    fn vector_presentation_proof_rejects_modified_q() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let (statement, witness) = vector_presentation_fixture();
        let proof = VectorPresentationProof::prove(&mut rng, &statement, &witness);
        let mut bad_statement = statement.clone();
        bad_statement
            .q_hidden
            .insert(1, bad_statement.q_hidden[&1] + point(1));
        assert!(!proof.verify(&bad_statement));
    }

    #[test]
    fn vector_presentation_proof_rejects_modified_p() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let (statement, witness) = vector_presentation_fixture();
        let proof = VectorPresentationProof::prove(&mut rng, &statement, &witness);
        let bad_statement = VectorPresentationStatement {
            p: statement.p + point(1),
            ..statement
        };
        assert!(!proof.verify(&bad_statement));
    }

    #[test]
    fn vector_presentation_proof_rejects_missing_index() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let (statement, witness) = vector_presentation_fixture();
        let proof = VectorPresentationProof::prove(&mut rng, &statement, &witness);
        let mut bad_statement = statement.clone();
        bad_statement.q_hidden.remove(&1);
        assert!(!proof.verify(&bad_statement));
    }

    fn vector_direct_issue_fixture() -> (VectorDirectIssueStatement, VectorDirectIssueWitness) {
        let g = generator();
        let h = point(17);
        let r = scalar(3);
        let r_inv = r.invert();
        let x = scalar(5);
        let v = scalar(11);
        let attributes = vec![scalar(2), scalar(4), scalar(6)];
        let malleable_indices = BTreeSet::from([0usize, 2usize]);
        let all_y_i = [scalar(7), scalar(13), scalar(19)];
        let y_i = all_y_i
            .iter()
            .copied()
            .enumerate()
            .collect::<BTreeMap<_, _>>();
        let r_x_g = r * (x * g);
        let r_y_i_g = all_y_i.iter().map(|y_i| r * (*y_i * g)).collect::<Vec<_>>();
        let d = vector_issue_d(r_x_g, &r_y_i_g, &attributes);
        let malleable_keys = malleable_indices
            .iter()
            .map(|idx| (*idx, r_inv * (v * r_y_i_g[*idx])))
            .collect();

        (
            VectorDirectIssueStatement {
                g,
                h,
                r_h: r * h,
                r_x_g,
                r_y_i_g,
                v_g: v * g,
                c: r_inv * (v * d),
                attributes,
                malleable_keys,
                malleable_indices,
            },
            VectorDirectIssueWitness {
                r_inv,
                r,
                x,
                y_i,
                v,
            },
        )
    }

    fn vector_delegatable_issue_fixture() -> (
        VectorDelegatableIssueStatement,
        VectorDelegatableIssueWitness,
    ) {
        let (direct, direct_witness) = vector_direct_issue_fixture();
        let z = scalar(23);
        (
            VectorDelegatableIssueStatement {
                g: direct.g,
                h: direct.h,
                r_h: direct.r_h,
                r_x_g: direct.r_x_g,
                r_y_i_g: direct.r_y_i_g,
                ev: direct_witness.v * direct.g + z * direct.h,
                ez: z * direct.g,
                c: direct.c,
                attributes: direct.attributes,
                malleable_keys: direct.malleable_keys,
                malleable_indices: direct.malleable_indices,
            },
            VectorDelegatableIssueWitness {
                r_inv: direct_witness.r_inv,
                r: direct_witness.r,
                x: direct_witness.x,
                y_i: direct_witness.y_i,
                v: direct_witness.v,
                z,
            },
        )
    }

    #[test]
    fn vector_direct_issue_paper_proof_accepts_valid_statement() {
        let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
        let (statement, witness) = vector_direct_issue_fixture();
        let proof = VectorDirectIssueProof::prove(&mut rng, &statement, &witness);
        assert!(proof.verify(&statement));
    }

    #[test]
    fn vector_direct_issue_paper_proof_rejects_modified_c() {
        let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
        let (statement, witness) = vector_direct_issue_fixture();
        let proof = VectorDirectIssueProof::prove(&mut rng, &statement, &witness);
        let bad_statement = VectorDirectIssueStatement {
            c: statement.c + point(1),
            ..statement
        };
        assert!(!proof.verify(&bad_statement));
    }

    #[test]
    fn vector_direct_issue_paper_proof_rejects_modified_malleable_key() {
        let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
        let (statement, witness) = vector_direct_issue_fixture();
        let proof = VectorDirectIssueProof::prove(&mut rng, &statement, &witness);
        let mut bad_statement = statement.clone();
        *bad_statement
            .malleable_keys
            .get_mut(&2)
            .expect("malleable key") += point(1);
        assert!(!proof.verify(&bad_statement));
    }

    #[test]
    fn vector_delegatable_issue_paper_proof_accepts_valid_statement() {
        let mut rng = ChaCha20Rng::from_seed([37u8; 32]);
        let (statement, witness) = vector_delegatable_issue_fixture();
        let proof = VectorDelegatableIssueProof::prove(&mut rng, &statement, &witness);
        assert!(proof.verify(&statement));
    }

    #[test]
    fn vector_delegatable_issue_paper_proof_rejects_modified_ev() {
        let mut rng = ChaCha20Rng::from_seed([37u8; 32]);
        let (statement, witness) = vector_delegatable_issue_fixture();
        let proof = VectorDelegatableIssueProof::prove(&mut rng, &statement, &witness);
        let bad_statement = VectorDelegatableIssueStatement {
            ev: statement.ev + point(1),
            ..statement
        };
        assert!(!proof.verify(&bad_statement));
    }

    #[test]
    fn vector_delegatable_issue_paper_proof_rejects_modified_c() {
        let mut rng = ChaCha20Rng::from_seed([37u8; 32]);
        let (statement, witness) = vector_delegatable_issue_fixture();
        let proof = VectorDelegatableIssueProof::prove(&mut rng, &statement, &witness);
        let bad_statement = VectorDelegatableIssueStatement {
            c: statement.c + point(1),
            ..statement
        };
        assert!(!proof.verify(&bad_statement));
    }

    #[test]
    fn vector_delegatable_issue_paper_proof_rejects_modified_malleable_key() {
        let mut rng = ChaCha20Rng::from_seed([37u8; 32]);
        let (statement, witness) = vector_delegatable_issue_fixture();
        let proof = VectorDelegatableIssueProof::prove(&mut rng, &statement, &witness);
        let mut bad_statement = statement.clone();
        *bad_statement
            .malleable_keys
            .get_mut(&0)
            .expect("malleable key") += point(1);
        assert!(!proof.verify(&bad_statement));
    }

    #[test]
    fn vector_issue_proof_placeholder_has_warning() {
        let proof = VectorIssueProofPlaceholder::new();
        assert!(proof.verify());
        assert!(proof.warning.contains("not implemented"));
    }

    #[test]
    fn vector_issue_paper_placeholder_mentions_updated_relation() {
        let proof = VectorIssuePaperProofPlaceholder::new();
        assert!(proof.verify());
        assert!(proof.warning.contains("rel_veciss"));
        assert!(proof.warning.contains("legacy"));
    }

    #[test]
    fn v2_subset_issuance_rejects_algebraically_consistent_zero_tags() {
        let mut rng = ChaCha20Rng::from_seed([41; 32]);
        let (mut s, mut w) = subset_direct_issue_fixture();
        w.v = Scalar::ZERO;
        s.v_x_g = Point::default();
        s.ev = Point::default();
        s.components
            .values_mut()
            .for_each(|p| *p = Point::default());
        assert!(!SubsetDirectIssueProof::prove(&mut rng, &s, &w).verify(&s));
        let (mut s, mut w) = subset_delegatable_issue_fixture();
        w.v = Scalar::ZERO;
        s.e = w.z * s.h;
        s.ev = Point::default();
        s.components
            .values_mut()
            .for_each(|p| *p = Point::default());
        assert!(!SubsetDelegatableIssueProof::prove(&mut rng, &s, &w).verify(&s));
    }

    fn subset_v2_fixture(mu: Scalar) -> (SubsetDelegateStatement, SubsetDelegateWitness) {
        let z_prime = scalar(13);
        (
            SubsetDelegateStatement {
                g: generator(),
                h: point(17),
                old_e: point(2),
                old_ev: point(3),
                old_ez: point(5),
                old_components: BTreeMap::from([(key(1), point(11)), (key(2), point(19))]),
                new_e: mu * point(2) + z_prime * point(17),
                new_ev: mu * point(3),
                new_ez: mu * point(5) + z_prime * generator(),
                new_components: BTreeMap::from([(key(1), mu * point(11))]),
            },
            SubsetDelegateWitness { mu, z_prime },
        )
    }

    #[test]
    fn v2_subset_delegation_masks_and_binds_dropped_components() {
        let mut rng = ChaCha20Rng::from_seed([42; 32]);
        let (s, w) = subset_v2_fixture(scalar(7));
        let proof = SubsetDelegateProof::prove(&mut rng, &s, &w);
        assert!(proof.verify(&s));
        assert_eq!(proof.a_components.len(), 1);
        for field in 0..7 {
            let mut bad = s.clone();
            match field {
                0 => bad.new_e += generator(),
                1 => bad.new_ev += generator(),
                2 => bad.new_ez += generator(),
                3 => *bad.old_components.get_mut(&key(2)).unwrap() += generator(),
                4 => bad.h += generator(),
                5 => bad.g += generator(),
                _ => {
                    bad.new_components.insert(key(3), point(11));
                }
            }
            assert!(!proof.verify(&bad), "mutation {field}");
        }
        let mut bad = proof.clone();
        bad.z_z_prime += Scalar::ONE;
        assert!(!bad.verify(&s));
        let mut bad = proof.clone();
        bad.z_mu += Scalar::ONE;
        assert!(!bad.verify(&s));
        let mut bad = proof.clone();
        bad.a_components.insert(key(3), point(1));
        assert!(!bad.verify(&s));
    }

    #[test]
    fn v2_subset_delegation_rejects_zero_scaling_even_with_valid_mask() {
        let mut rng = ChaCha20Rng::from_seed([43; 32]);
        let (s, w) = subset_v2_fixture(Scalar::ZERO);
        assert!(!SubsetDelegateProof::prove(&mut rng, &s, &w).verify(&s));
    }

    fn vector_v2_fixture() -> (VectorDelegateStatement, VectorDelegateWitness) {
        let mu = scalar(7);
        let z_prime = scalar(13);
        let old_message = Message {
            attributes: vec![scalar(2), scalar(3)],
            malleable_indices: BTreeSet::from([0, 1]),
        };
        let new_message = Message {
            attributes: vec![scalar(5), scalar(3)],
            malleable_indices: BTreeSet::from([1]),
        };
        (
            VectorDelegateStatement {
                g: generator(),
                h: point(17),
                old_ev: point(2),
                old_ez: point(3),
                old_c: point(5),
                old_message,
                new_message,
                old_malleable_keys: BTreeMap::from([(0, point(11)), (1, point(19))]),
                new_malleable_keys: BTreeMap::from([(1, mu * point(19))]),
                new_ev: mu * point(2) + z_prime * point(17),
                new_ez: mu * point(3) + z_prime * generator(),
                new_c: mu * (point(5) + scalar(3) * point(11)),
            },
            VectorDelegateWitness { mu, z_prime },
        )
    }

    #[test]
    fn v2_vector_delegation_proves_retained_keys_with_shared_mu() {
        let mut rng = ChaCha20Rng::from_seed([44; 32]);
        let (s, w) = vector_v2_fixture();
        let proof = VectorDelegateProof::prove(&mut rng, &s, &w);
        assert!(proof.verify(&s));
        for field in 0..10 {
            let mut bad = s.clone();
            match field {
                0 => *bad.new_malleable_keys.get_mut(&1).unwrap() += generator(),
                1 => *bad.old_malleable_keys.get_mut(&1).unwrap() += generator(),
                2 => bad.new_ev += generator(),
                3 => bad.new_ez += generator(),
                4 => bad.h += generator(),
                5 => bad.new_message.attributes[1] += Scalar::ONE,
                // Change both values so admissibility and adjusted C remain unchanged:
                // only binding the full messages catches this.
                6 => {
                    bad.old_message.attributes[1] += Scalar::ONE;
                    bad.new_message.attributes[1] += Scalar::ONE;
                }
                7 => {
                    bad.new_malleable_keys.remove(&1);
                }
                8 => {
                    bad.new_malleable_keys.insert(2, point(1));
                }
                _ => {
                    bad.old_message.malleable_indices.insert(99);
                }
            }
            assert!(!proof.verify(&bad), "mutation {field}");
        }
        let mut bad = proof.clone();
        bad.z_z_prime += Scalar::ONE;
        assert!(!bad.verify(&s));
        let mut bad = proof.clone();
        bad.z_mu += Scalar::ONE;
        assert!(!bad.verify(&s));
        for mode in 0..3 {
            let mut bad = proof.clone();
            match mode {
                0 => {
                    bad.a_malleable_keys.clear();
                }
                1 => {
                    bad.a_malleable_keys.insert(2, point(1));
                }
                _ => {
                    let p = bad.a_malleable_keys.remove(&1).unwrap();
                    bad.a_malleable_keys.insert(0, p);
                }
            }
            assert!(!bad.verify(&s));
        }
        // Produce a fresh proof after changing a retained key, so the transcript is
        // internally consistent: the shared-scalar equation itself must reject it.
        let mut bad = s.clone();
        *bad.new_malleable_keys.get_mut(&1).unwrap() += generator();
        assert!(!VectorDelegateProof::prove(&mut rng, &bad, &w).verify(&bad));
    }

    #[test]
    fn v2_vector_issuance_full_coefficient_domain_for_empty_partial_full_l() {
        let mut rng = ChaCha20Rng::from_seed([45; 32]);
        for indices in [
            BTreeSet::new(),
            BTreeSet::from([0, 2]),
            BTreeSet::from([0, 1, 2]),
        ] {
            let (mut direct, w) = vector_direct_issue_fixture();
            direct.malleable_indices = indices.clone();
            direct.malleable_keys = indices
                .iter()
                .map(|i| (*i, w.v * w.y_i[i] * direct.g))
                .collect();
            let p = VectorDirectIssueProof::prove(&mut rng, &direct, &w);
            assert!(p.verify(&direct));
            assert_eq!(p.a_malleable_keys.len(), indices.len());
            assert_eq!(p.a_y.len(), 3);
            assert_eq!(p.z_y.len(), 3);
            let (mut encrypted, ew) = vector_delegatable_issue_fixture();
            encrypted.malleable_indices = indices;
            encrypted.malleable_keys = direct.malleable_keys.clone();
            let ep = VectorDelegatableIssueProof::prove(&mut rng, &encrypted, &ew);
            assert!(ep.verify(&encrypted));
            assert_eq!(ep.a_y.len(), 3);
            assert_eq!(ep.z_y.len(), 3);
            for mode in 0..4 {
                let mut bad = p.clone();
                let mut ebad = ep.clone();
                match mode {
                    0 => {
                        bad.z_y.remove(&1);
                        ebad.z_y.remove(&1);
                    }
                    1 => {
                        bad.a_y.remove(&1);
                        ebad.a_y.remove(&1);
                    }
                    2 => {
                        *bad.z_y.get_mut(&1).unwrap() += Scalar::ONE;
                        *ebad.z_y.get_mut(&1).unwrap() += Scalar::ONE;
                    }
                    _ => {
                        let v = bad.z_y.remove(&1).unwrap();
                        bad.z_y.insert(99, v);
                        let v = ebad.z_y.remove(&1).unwrap();
                        ebad.z_y.insert(99, v);
                    }
                }
                assert!(!bad.verify(&direct));
                assert!(!ebad.verify(&encrypted));
            }
        }
    }

    #[test]
    fn v2_vector_direct_zero_plaintext_rejected_encrypted_relation_allows_it() {
        let mut rng = ChaCha20Rng::from_seed([46; 32]);
        let (mut s, mut w) = vector_direct_issue_fixture();
        w.v = Scalar::ZERO;
        s.v_g = Point::default();
        s.c = Point::default();
        s.malleable_keys
            .values_mut()
            .for_each(|p| *p = Point::default());
        assert!(!VectorDirectIssueProof::prove(&mut rng, &s, &w).verify(&s));
        let (mut s, mut w) = vector_delegatable_issue_fixture();
        w.v = Scalar::ZERO;
        s.ev = w.z * s.h;
        s.c = Point::default();
        s.malleable_keys
            .values_mut()
            .for_each(|p| *p = Point::default());
        assert!(VectorDelegatableIssueProof::prove(&mut rng, &s, &w).verify(&s));
    }

    #[test]
    fn v2_presentation_binds_complete_issuer_and_public_parameters() {
        let mut rng = ChaCha20Rng::from_seed([47; 32]);
        let (s, w) = vector_presentation_fixture();
        let p = VectorPresentationProof::prove(&mut rng, &s, &w);
        for mode in 0..5 {
            let mut bad = s.clone();
            match mode {
                0 => bad.r_x_g += generator(),
                1 => bad.r_y_i_g[0] += generator(), // disclosed coefficient, absent from equations
                2 => bad.h += generator(),
                3 => bad.g += generator(),
                _ => {
                    bad.q_hidden.insert(99, point(1));
                }
            }
            assert!(!p.verify(&bad));
        }
    }

    #[test]
    fn v2_rejects_legacy_subset_direct_proof_domain() {
        let mut rng = ChaCha20Rng::from_seed([48; 32]);
        let (s, w) = subset_direct_issue_fixture();
        let rx = random_scalar(&mut rng);
        let ry = random_scalar(&mut rng);
        let rv = random_scalar(&mut rng);
        let mut p = SubsetDirectIssueProof {
            a_x: rx * s.g,
            a_y: ry * s.g,
            a_ev: rv * s.g,
            a_v: rv * s.x_g,
            a_components: s.components.iter().map(|(k, p)| (*k, ry * p)).collect(),
            z_x: Scalar::ZERO,
            z_y: Scalar::ZERO,
            z_v: Scalar::ZERO,
        };
        // Exact v1 transcript: no collection lengths, and the old domain.
        let mut t = Transcript::new(b"dkvac-subset-direct-issue-v1");
        for (label, point) in [
            (b"g".as_slice(), s.g),
            (b"x_g", s.x_g),
            (b"y_g", s.y_g),
            (b"v_x_g", s.v_x_g),
            (b"ev", s.ev),
        ] {
            transcript_append_point(&mut t, label, &point);
        }
        for (key, point) in &s.components {
            t.append_message(b"component_key", &key.0);
            transcript_append_point(&mut t, b"component_value", point);
        }
        append_subset_direct_issue_commitments(
            &mut t,
            &p.a_x,
            &p.a_y,
            &p.a_ev,
            &p.a_v,
            &p.a_components,
        );
        let c = transcript_challenge_scalar(&mut t, b"c");
        p.z_x = rx + c * w.x;
        p.z_y = ry + c * w.y;
        p.z_v = rv + c * w.v;
        assert_eq!(p.z_v * s.g, p.a_ev + c * s.ev);
        assert!(!p.verify(&s));
    }
}
