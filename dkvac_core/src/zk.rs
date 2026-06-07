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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubsetDelegateProof {
    pub a_e: Point,
    pub a_ev: Point,
    pub a_ez: Point,
    pub a_components: BTreeMap<ScalarBytes, Point>,
    pub z_mu: Scalar,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorDelegateProof {
    pub a_ev: Point,
    pub a_ez: Point,
    pub a_c: Point,
    pub z_mu: Scalar,
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
}
