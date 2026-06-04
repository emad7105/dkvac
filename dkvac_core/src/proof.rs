use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DummyProof;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProofStatement {
    Inst1Issue,
    Inst1Delegate,
    Inst2Issue,
    Inst2Delegate,
    Inst2Show,
}

pub trait ProofSystem {
    type Proof;

    fn prove(statement: ProofStatement) -> Self::Proof;

    fn verify(statement: ProofStatement, proof: &Self::Proof) -> bool;
}

pub struct DummyProofSystem;

impl ProofSystem for DummyProofSystem {
    type Proof = DummyProof;

    fn prove(_statement: ProofStatement) -> Self::Proof {
        DummyProof
    }

    fn verify(_statement: ProofStatement, _proof: &Self::Proof) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_proof_verification_returns_true() {
        let proof = DummyProofSystem::prove(ProofStatement::Inst1Issue);
        assert!(DummyProofSystem::verify(ProofStatement::Inst1Issue, &proof));
    }
}
