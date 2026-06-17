use crate::group::{Point, Scalar, random_scalar};
use crate::instantiation1::ScalarBytes;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsetDelegateProof {
    pub a_e: Point,
    pub a_ev: Point,
    pub a_ez: Point,
    pub a_components: BTreeMap<ScalarBytes, Point>,
    pub z_mu: Scalar,
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
    pub old_ev: Point,
    pub old_ez: Point,
    pub old_c_adjusted: Point,
    pub new_ev: Point,
    pub new_ez: Point,
    pub new_c: Point,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorDelegateWitness {
    pub mu: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorDelegateProof {
    pub a_ev: Point,
    pub a_ez: Point,
    pub a_c: Point,
    pub z_mu: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorPresentationStatement {
    pub r_h: Point,
    pub y_i_points: BTreeMap<usize, Point>,
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
        let a_e = rho * statement.old_e;
        let a_ev = rho * statement.old_ev;
        let a_ez = rho * statement.old_ez;
        let a_components = statement
            .old_components
            .iter()
            .map(|(key, point)| (*key, rho * *point))
            .collect::<BTreeMap<_, _>>();

        let mut transcript = Transcript::new(b"dkvac-subset-delegate-v1");
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
        }
    }

    pub fn verify(&self, statement: &SubsetDelegateStatement) -> bool {
        if statement.old_components.len() != statement.new_components.len()
            || statement.old_components.len() != self.a_components.len()
        {
            return false;
        }

        let mut transcript = Transcript::new(b"dkvac-subset-delegate-v1");
        append_subset_delegate_statement(&mut transcript, statement);
        transcript_append_point(&mut transcript, b"a_e", &self.a_e);
        transcript_append_point(&mut transcript, b"a_ev", &self.a_ev);
        transcript_append_point(&mut transcript, b"a_ez", &self.a_ez);
        for (key, point) in &self.a_components {
            transcript.append_message(b"a_component_key", &key.0);
            transcript_append_point(&mut transcript, b"a_component_value", point);
        }
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        if self.z_mu * statement.old_e != self.a_e + c * statement.new_e {
            return false;
        }
        if self.z_mu * statement.old_ev != self.a_ev + c * statement.new_ev {
            return false;
        }
        if self.z_mu * statement.old_ez != self.a_ez + c * statement.new_ez {
            return false;
        }

        for (key, old_component) in &statement.old_components {
            let Some(new_component) = statement.new_components.get(key) else {
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

        let mut transcript = Transcript::new(b"dkvac-subset-direct-issue-v1");
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
        if statement.components.len() != self.a_components.len() {
            return false;
        }

        let mut transcript = Transcript::new(b"dkvac-subset-direct-issue-v1");
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

        let mut transcript = Transcript::new(b"dkvac-subset-delegatable-issue-v1");
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
        if statement.components.len() != self.a_components.len() {
            return false;
        }

        let mut transcript = Transcript::new(b"dkvac-subset-delegatable-issue-v1");
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

impl VectorDelegateProof {
    pub fn prove<R: CryptoRng + RngCore>(
        rng: &mut R,
        statement: &VectorDelegateStatement,
        witness: &VectorDelegateWitness,
    ) -> Self {
        let rho = random_scalar(rng);
        let a_ev = rho * statement.old_ev;
        let a_ez = rho * statement.old_ez;
        let a_c = rho * statement.old_c_adjusted;

        let mut transcript = Transcript::new(b"dkvac-vector-delegate-v1");
        append_vector_delegate_statement(&mut transcript, statement);
        transcript_append_point(&mut transcript, b"a_ev", &a_ev);
        transcript_append_point(&mut transcript, b"a_ez", &a_ez);
        transcript_append_point(&mut transcript, b"a_c", &a_c);
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        Self {
            a_ev,
            a_ez,
            a_c,
            z_mu: rho + c * witness.mu,
        }
    }

    pub fn verify(&self, statement: &VectorDelegateStatement) -> bool {
        let mut transcript = Transcript::new(b"dkvac-vector-delegate-v1");
        append_vector_delegate_statement(&mut transcript, statement);
        transcript_append_point(&mut transcript, b"a_ev", &self.a_ev);
        transcript_append_point(&mut transcript, b"a_ez", &self.a_ez);
        transcript_append_point(&mut transcript, b"a_c", &self.a_c);
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        self.z_mu * statement.old_ev == self.a_ev + c * statement.new_ev
            && self.z_mu * statement.old_ez == self.a_ez + c * statement.new_ez
            && self.z_mu * statement.old_c_adjusted == self.a_c + c * statement.new_c
    }
}

impl VectorPresentationProof {
    pub fn prove<R: CryptoRng + RngCore>(
        rng: &mut R,
        statement: &VectorPresentationStatement,
        witness: &VectorPresentationWitness,
    ) -> Self {
        let indices = statement.q_hidden.keys().copied().collect::<Vec<_>>();
        assert!(matching_hidden_index_sets(
            &statement.y_i_points,
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

        let a_p = indices.iter().fold(-(rho_mu_prime * statement.r_h), |acc, idx| {
            acc + rho_beta[idx] * statement.y_i_points[idx]
        });
        let a_q = indices
            .iter()
            .map(|idx| {
                (
                    *idx,
                    rho_s[idx] * statement.v_prime + rho_beta[idx] * crate::group::generator(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut transcript = Transcript::new(b"dkvac-vector-presentation-v1");
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
        if !matching_hidden_index_sets(
            &statement.y_i_points,
            &statement.q_hidden,
            &self.z_beta,
            &self.z_s,
        ) {
            return false;
        }
        if self.a_q.keys().copied().collect::<Vec<_>>()
            != statement.q_hidden.keys().copied().collect::<Vec<_>>()
        {
            return false;
        }

        let indices = statement.q_hidden.keys().copied().collect::<Vec<_>>();
        let mut transcript = Transcript::new(b"dkvac-vector-presentation-v1");
        append_vector_presentation_statement(&mut transcript, statement);
        transcript_append_point(&mut transcript, b"a_p", &self.a_p);
        for (idx, point) in &self.a_q {
            transcript_append_usize(&mut transcript, b"a_q_idx", *idx);
            transcript_append_point(&mut transcript, b"a_q_point", point);
        }
        let c = transcript_challenge_scalar(&mut transcript, b"c");

        let lhs_p = indices.iter().fold(-(self.z_mu_prime * statement.r_h), |acc, idx| {
            acc + self.z_beta[idx] * statement.y_i_points[idx]
        });
        let rhs_p = self.a_p + c * statement.p;
        if lhs_p != rhs_p {
            return false;
        }

        for idx in indices {
            let lhs_q = self.z_s[&idx] * statement.v_prime
                + self.z_beta[&idx] * crate::group::generator();
            let rhs_q = self.a_q[&idx] + c * statement.q_hidden[&idx];
            if lhs_q != rhs_q {
                return false;
            }
        }

        true
    }
}

impl VectorIssueProofPlaceholder {
    pub fn new() -> Self {
        Self {
            warning: "WARNING: vector issuance proof is not implemented. This placeholder is only for algebraic protocol testing.".to_string(),
        }
    }

    pub fn verify(&self) -> bool {
        // WARNING: vector issuance proof is not implemented.
        // This placeholder is only for algebraic protocol testing.
        true
    }
}

impl VectorIssuePaperProofPlaceholder {
    pub fn new() -> Self {
        Self {
            warning: "WARNING: exact paper rel_veciss is not implemented. The updated relation contains non-linear witness products such as rC = vD. Do not use this placeholder for security claims.".to_string(),
        }
    }

    pub fn verify(&self) -> bool {
        // WARNING: exact paper rel_veciss is not implemented.
        // The updated relation contains non-linear witness products such as rC = vD.
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

fn append_vector_delegate_statement(
    transcript: &mut Transcript,
    statement: &VectorDelegateStatement,
) {
    transcript_append_point(transcript, b"old_ev", &statement.old_ev);
    transcript_append_point(transcript, b"old_ez", &statement.old_ez);
    transcript_append_point(transcript, b"old_c_adjusted", &statement.old_c_adjusted);
    transcript_append_point(transcript, b"new_ev", &statement.new_ev);
    transcript_append_point(transcript, b"new_ez", &statement.new_ez);
    transcript_append_point(transcript, b"new_c", &statement.new_c);
}

fn append_vector_presentation_statement(
    transcript: &mut Transcript,
    statement: &VectorPresentationStatement,
) {
    transcript_append_point(transcript, b"r_h", &statement.r_h);
    for (idx, point) in &statement.y_i_points {
        transcript_append_usize(transcript, b"y_idx", *idx);
        transcript_append_point(transcript, b"y_point", point);
    }
    transcript_append_point(transcript, b"v_prime", &statement.v_prime);
    transcript_append_point(transcript, b"p", &statement.p);
    for (idx, point) in &statement.q_hidden {
        transcript_append_usize(transcript, b"q_idx", *idx);
        transcript_append_point(transcript, b"q_point", point);
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

fn matching_hidden_index_sets<T, U, V, W>(
    y_i_points: &BTreeMap<usize, T>,
    q_hidden: &BTreeMap<usize, U>,
    hidden_attributes: &BTreeMap<usize, V>,
    beta: &BTreeMap<usize, W>,
) -> bool {
    let y_keys = y_i_points.keys().copied().collect::<Vec<_>>();
    let q_keys = q_hidden.keys().copied().collect::<Vec<_>>();
    let s_keys = hidden_attributes.keys().copied().collect::<Vec<_>>();
    let b_keys = beta.keys().copied().collect::<Vec<_>>();
    y_keys == q_keys && q_keys == s_keys && s_keys == b_keys
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
            old_e: point(2),
            old_ev: point(3),
            old_ez: point(5),
            old_components,
            new_e: mu * point(2),
            new_ev: mu * point(3),
            new_ez: mu * point(5),
            new_components,
        };
        let witness = SubsetDelegateWitness { mu };
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
            &SubsetDelegateWitness { mu },
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
            old_c_adjusted: point(8),
            new_ev: mu * point(4),
            new_ez: mu * point(6),
            new_c: mu * point(8),
        };
        let proof = VectorDelegateProof::prove(&mut rng, &statement, &VectorDelegateWitness { mu });
        assert!(proof.verify(&statement));
    }

    #[test]
    fn vector_delegation_proof_rejects_modified_new_c() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let mu = scalar(9);
        let valid_statement = VectorDelegateStatement {
            old_ev: point(4),
            old_ez: point(6),
            old_c_adjusted: point(8),
            new_ev: mu * point(4),
            new_ez: mu * point(6),
            new_c: mu * point(8),
        };
        let proof =
            VectorDelegateProof::prove(&mut rng, &valid_statement, &VectorDelegateWitness { mu });
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

    fn subset_direct_issue_fixture(
    ) -> (SubsetDirectIssueStatement, SubsetDirectIssueWitness) {
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

    fn subset_delegatable_issue_fixture(
    ) -> (SubsetDelegatableIssueStatement, SubsetDelegatableIssueWitness) {
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
        *bad_statement.components.get_mut(&target).expect("component") += point(1);
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
        *bad_statement.components.get_mut(&target).expect("component") += point(1);
        assert!(!proof.verify(&bad_statement));
    }

    fn vector_presentation_fixture() -> (
        VectorPresentationStatement,
        VectorPresentationWitness,
    ) {
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
            .fold(-(scalar(31) * r_h), |acc, (idx, y_i)| acc + beta[idx] * *y_i);
        (
            VectorPresentationStatement {
                r_h,
                y_i_points,
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
        assert!(!proof.verify(&VectorPresentationStatement {
            q_hidden: statement
                .q_hidden
                .iter()
                .map(|(idx, point)| {
                    if *idx == 1 {
                        (*idx, witness.hidden_attributes[idx] * statement.v_prime + witness.beta[idx] * generator())
                    } else {
                        (*idx, *point)
                    }
                })
                .collect(),
            ..statement
        }));
    }

    #[test]
    fn vector_presentation_proof_rejects_modified_q() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let (statement, witness) = vector_presentation_fixture();
        let proof = VectorPresentationProof::prove(&mut rng, &statement, &witness);
        let mut bad_statement = statement.clone();
        bad_statement.q_hidden.insert(1, bad_statement.q_hidden[&1] + point(1));
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
        assert!(proof.warning.contains("non-linear"));
    }
}
