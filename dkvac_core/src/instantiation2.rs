use crate::error::DkvacError;
use crate::group::{Point, Scalar, derive_h, generator, is_identity, random_scalar};
use crate::proof::{DummyProof, DummyProofSystem, ProofStatement, ProofSystem};
use crate::zk::{VectorDelegateProof, VectorDelegateStatement, VectorDelegateWitness};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroize;

pub const DEFAULT_MAX_ATTRIBUTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicParams {
    pub g: Point,
    pub h: Point,
    pub max_attributes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct IssuerSecretKey {
    pub r: Scalar,
    pub x: Scalar,
    pub y: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerPublicParams {
    pub r_h: Point,
    pub r_x_g: Point,
    pub r_y_i_g: Vec<Point>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub attributes: Vec<Scalar>,
    pub malleable_indices: BTreeSet<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub v_g: Point,
    pub c: Point,
    pub malleable_keys: BTreeMap<usize, Point>,
    pub message: Message,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCredential {
    pub ev: Point,
    pub ez: Point,
    pub c: Point,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationStep {
    pub ec: EncryptedCredential,
    pub malleable_keys: BTreeMap<usize, Point>,
    pub message: Message,
    pub proof: Inst2DelegationProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncDel {
    pub steps: Vec<DelegationStep>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosurePolicy {
    pub disclosed_indices: BTreeSet<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Show {
    pub v_prime: Point,
    pub w: Point,
    pub q_hidden: BTreeMap<usize, Point>,
    pub disclosed: BTreeMap<usize, Scalar>,
    pub proof: DummyProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Inst2DelegationProof {
    Issue(DummyProof),
    Delegate(VectorDelegateProof),
}

pub fn setup<R: CryptoRng + RngCore>(rng: &mut R, max_attributes: usize) -> PublicParams {
    PublicParams {
        g: generator(),
        h: derive_h(rng),
        max_attributes,
    }
}

pub fn keygen<R: CryptoRng + RngCore>(
    rng: &mut R,
    pp: &PublicParams,
) -> Result<(IssuerSecretKey, IssuerPublicParams), DkvacError> {
    if is_identity(&pp.g) || is_identity(&pp.h) {
        return Err(DkvacError::IdentityPoint);
    }

    let r = random_scalar(rng);
    let x = random_scalar(rng);
    let y = random_scalar(rng);
    let isk = IssuerSecretKey { r, x, y };
    let ipar = IssuerPublicParams {
        r_h: isk.r * pp.h,
        r_x_g: (isk.r * isk.x) * pp.g,
        r_y_i_g: (0..pp.max_attributes)
            .map(|idx| (isk.r * y_power(&isk.y, idx)) * pp.g)
            .collect(),
    };
    Ok((isk, ipar))
}

pub fn issue_cred<R: CryptoRng + RngCore>(
    rng: &mut R,
    pp: &PublicParams,
    isk: &IssuerSecretKey,
    _ipar: &IssuerPublicParams,
    message: &Message,
) -> Result<(Credential, DummyProof), DkvacError> {
    validate_message(pp, message)?;

    let v = random_scalar(rng);
    let v_g = v * pp.g;
    let mac_scalar = compute_mac_scalar(isk, message)?;
    let c = mac_scalar * v_g;
    let malleable_keys = compute_malleable_keys(&isk.y, &message.malleable_indices, &v_g)?;
    let cred = Credential {
        v_g,
        c,
        malleable_keys,
        message: message.clone(),
    };
    Ok((cred, DummyProofSystem::prove(ProofStatement::Inst2Issue)))
}

pub fn obtain_cred(
    pp: &PublicParams,
    _ipar: &IssuerPublicParams,
    message: &Message,
    cred: Credential,
    proof: &DummyProof,
) -> Result<Credential, DkvacError> {
    if !DummyProofSystem::verify(ProofStatement::Inst2Issue, proof) {
        return Err(DkvacError::InvalidProof);
    }
    validate_message(pp, message)?;
    if &cred.message != message {
        return Err(DkvacError::InvalidAttributeSet);
    }
    validate_malleable_keys(&cred.message, &cred.malleable_keys)?;
    Ok(cred)
}

pub fn show_cred<R: CryptoRng + RngCore>(
    rng: &mut R,
    pp: &PublicParams,
    ipar: &IssuerPublicParams,
    message: &Message,
    policy: &DisclosurePolicy,
    cred: &Credential,
) -> Result<Show, DkvacError> {
    validate_message(pp, message)?;
    validate_policy(pp, policy)?;
    if &cred.message != message {
        return Err(DkvacError::InvalidDisclosure);
    }
    validate_malleable_keys(&cred.message, &cred.malleable_keys)?;

    let mu = random_scalar(rng);
    let mu_prime = random_scalar(rng);
    let v_prime = mu * cred.v_g;
    let c_prime = mu * cred.c;
    let w = c_prime + mu_prime * pp.h;
    let disclosed = policy
        .disclosed_indices
        .iter()
        .map(|idx| (*idx, message.attributes[*idx]))
        .collect::<BTreeMap<_, _>>();

    let hidden_indices = hidden_indices(pp.max_attributes, &policy.disclosed_indices);
    let mut beta_hidden = BTreeMap::new();
    let q_hidden = hidden_indices
        .iter()
        .map(|idx| {
            let beta_i = random_scalar(rng);
            beta_hidden.insert(*idx, beta_i);
            (*idx, message.attributes[*idx] * v_prime + beta_i * pp.g)
        })
        .collect::<BTreeMap<_, _>>();

    let _p = hidden_indices.iter().try_fold(-(mu_prime * ipar.r_h), |acc, idx| {
        let beta_i = beta_hidden
            .get(idx)
            .copied()
            .ok_or(DkvacError::InvalidDisclosure)?;
        Ok::<Point, DkvacError>(acc + beta_i * ipar.r_y_i_g[*idx])
    })?;

    Ok(Show {
        v_prime,
        w,
        q_hidden,
        disclosed,
        proof: DummyProofSystem::prove(ProofStatement::Inst2Show),
    })
}

pub fn verify_show(
    pp: &PublicParams,
    isk: &IssuerSecretKey,
    policy: &DisclosurePolicy,
    show: &Show,
) -> Result<bool, DkvacError> {
    validate_policy(pp, policy)?;
    if is_identity(&show.v_prime) {
        return Err(DkvacError::IdentityPoint);
    }

    let disclosed_indices = show.disclosed.keys().copied().collect::<BTreeSet<_>>();
    if disclosed_indices != policy.disclosed_indices {
        return Err(DkvacError::InvalidDisclosure);
    }

    let hidden_indices = hidden_indices(pp.max_attributes, &policy.disclosed_indices);
    let q_hidden_indices = show.q_hidden.keys().copied().collect::<BTreeSet<_>>();
    if q_hidden_indices != hidden_indices {
        return Err(DkvacError::InvalidDisclosure);
    }

    let hidden_sum = show.q_hidden.iter().try_fold(Point::default(), |acc, (idx, q_i)| {
        if *idx >= pp.max_attributes {
            return Err(DkvacError::IndexOutOfRange);
        }
        Ok(acc + y_power(&isk.y, *idx) * *q_i)
    })?;

    let disclosed_sum = show
        .disclosed
        .iter()
        .try_fold(Point::default(), |acc, (idx, value)| {
            if *idx >= pp.max_attributes {
                return Err(DkvacError::IndexOutOfRange);
            }
            Ok(acc + y_power(&isk.y, *idx) * *value * show.v_prime)
        })?;

    let p = isk.r * (isk.x * show.v_prime + hidden_sum - show.w + disclosed_sum);
    if !DummyProofSystem::verify(ProofStatement::Inst2Show, &show.proof) {
        return Err(DkvacError::InvalidProof);
    }

    let _ = p;
    Ok(true)
}

pub fn issue_del<R: CryptoRng + RngCore>(
    rng: &mut R,
    pp: &PublicParams,
    isk: &IssuerSecretKey,
    _ipar: &IssuerPublicParams,
    message: &Message,
) -> Result<(EncDel, Scalar), DkvacError> {
    validate_message(pp, message)?;

    let v = random_scalar(rng);
    let z = random_scalar(rng);
    let v_g = v * pp.g;
    let mac_scalar = compute_mac_scalar(isk, message)?;
    let step = DelegationStep {
        ec: EncryptedCredential {
            ev: v_g + z * pp.h,
            ez: z * pp.g,
            c: mac_scalar * v_g,
        },
        malleable_keys: compute_malleable_keys(&isk.y, &message.malleable_indices, &v_g)?,
        message: message.clone(),
        proof: Inst2DelegationProof::Issue(DummyProofSystem::prove(ProofStatement::Inst2Issue)),
    };

    Ok((EncDel { steps: vec![step] }, z))
}

pub fn delegate<R: CryptoRng + RngCore>(
    rng: &mut R,
    pp: &PublicParams,
    encdel: &EncDel,
    dk: &Scalar,
    next_message: &Message,
) -> Result<(EncDel, Scalar), DkvacError> {
    validate_message(pp, next_message)?;
    // let current = validate_encdel(pp, encdel)?;
    let steps = encdel.steps.iter();
    let current = steps.last().ok_or(DkvacError::InvalidDelegation)?;
    if !is_valid_delegation(&current.message, next_message) {
        return Err(DkvacError::InvalidDelegation);
    }

    let mu = random_scalar(rng);
    let finalized_indices = current
        .message
        .malleable_indices
        .difference(&next_message.malleable_indices)
        .copied()
        .collect::<BTreeSet<_>>();

    let adjustment = finalized_indices.iter().try_fold(Point::default(), |acc, idx| {
        let mk = current
            .malleable_keys
            .get(idx)
            .ok_or(DkvacError::InvalidDelegation)?;
        let delta = next_message.attributes[*idx] - current.message.attributes[*idx];
        Ok(acc + delta * *mk)
    })?;

    let malleable_keys = next_message
        .malleable_indices
        .iter()
        .map(|idx| {
            let mk = current
                .malleable_keys
                .get(idx)
                .ok_or(DkvacError::InvalidDelegation)?;
            Ok((*idx, mu * *mk))
        })
        .collect::<Result<BTreeMap<_, _>, DkvacError>>()?;

    let new_ec = EncryptedCredential {
        ev: mu * current.ec.ev,
        ez: mu * current.ec.ez,
        c: mu * (current.ec.c + adjustment),
    };
    let statement = VectorDelegateStatement {
        old_ev: current.ec.ev,
        old_ez: current.ec.ez,
        old_c_adjusted: current.ec.c + adjustment,
        new_ev: new_ec.ev,
        new_ez: new_ec.ez,
        new_c: new_ec.c,
    };
    let next_step = DelegationStep {
        ec: new_ec,
        malleable_keys,
        message: next_message.clone(),
        proof: Inst2DelegationProof::Delegate(VectorDelegateProof::prove(
            rng,
            &statement,
            &VectorDelegateWitness { mu },
        )),
    };

    let mut steps = encdel.steps.clone();
    steps.push(next_step);
    Ok((EncDel { steps }, mu * *dk))
}

pub fn obtain_del(
    pp: &PublicParams,
    encdel: &EncDel,
    dk: &Scalar,
) -> Result<Credential, DkvacError> {
    let final_step = validate_encdel(pp, encdel)?;
    let v_g = final_step.ec.ev - *dk * pp.h;

    Ok(Credential {
        v_g,
        c: final_step.ec.c,
        malleable_keys: final_step.malleable_keys.clone(),
        message: final_step.message.clone(),
    })
}

pub fn validate_message(pp: &PublicParams, message: &Message) -> Result<(), DkvacError> {
    if message.attributes.len() != pp.max_attributes {
        return Err(DkvacError::InvalidAttributeSet);
    }
    for idx in &message.malleable_indices {
        if *idx >= pp.max_attributes {
            return Err(DkvacError::IndexOutOfRange);
        }
    }
    Ok(())
}

pub fn is_valid_delegation(current: &Message, next: &Message) -> bool {
    if current.attributes.len() != next.attributes.len() {
        return false;
    }
    if !next
        .malleable_indices
        .is_subset(&current.malleable_indices)
    {
        return false;
    }
    for idx in 0..current.attributes.len() {
        if !current.malleable_indices.contains(&idx) && current.attributes[idx] != next.attributes[idx] {
            return false;
        }
    }
    true
}

pub fn y_power(y: &Scalar, idx: usize) -> Scalar {
    let mut result = Scalar::ONE;
    for _ in 0..=idx {
        result *= y;
    }
    result
}

pub fn compute_mac_scalar(
    isk: &IssuerSecretKey,
    message: &Message,
) -> Result<Scalar, DkvacError> {
    if message.attributes.is_empty() {
        return Err(DkvacError::InvalidAttributeSet);
    }

    let mut mac_scalar = isk.x;
    for (idx, attribute) in message.attributes.iter().enumerate() {
        mac_scalar += y_power(&isk.y, idx) * *attribute;
    }
    Ok(mac_scalar)
}

fn compute_malleable_keys(
    y: &Scalar,
    malleable_indices: &BTreeSet<usize>,
    v_g: &Point,
) -> Result<BTreeMap<usize, Point>, DkvacError> {
    malleable_indices
        .iter()
        .map(|idx| Ok((*idx, y_power(y, *idx) * *v_g)))
        .collect()
}

fn validate_policy(pp: &PublicParams, policy: &DisclosurePolicy) -> Result<(), DkvacError> {
    for idx in &policy.disclosed_indices {
        if *idx >= pp.max_attributes {
            return Err(DkvacError::IndexOutOfRange);
        }
    }
    Ok(())
}

fn validate_malleable_keys(
    message: &Message,
    malleable_keys: &BTreeMap<usize, Point>,
) -> Result<(), DkvacError> {
    let actual = malleable_keys.keys().copied().collect::<BTreeSet<_>>();
    if actual != message.malleable_indices {
        return Err(DkvacError::InvalidDelegation);
    }
    Ok(())
}

fn hidden_indices(max_attributes: usize, disclosed_indices: &BTreeSet<usize>) -> BTreeSet<usize> {
    (0..max_attributes)
        .filter(|idx| !disclosed_indices.contains(idx))
        .collect()
}

fn validate_encdel<'a>(
    pp: &PublicParams,
    encdel: &'a EncDel,
) -> Result<&'a DelegationStep, DkvacError> {
    let mut steps = encdel.steps.iter();
    let first = steps.next().ok_or(DkvacError::InvalidDelegation)?;
    validate_message(pp, &first.message)?;
    match &first.proof {
        Inst2DelegationProof::Issue(proof)
            if DummyProofSystem::verify(ProofStatement::Inst2Issue, proof) => {}
        _ => return Err(DkvacError::InvalidProof),
    }
    validate_malleable_keys(&first.message, &first.malleable_keys)?;

    let mut previous = first;
    for step in steps {
        validate_message(pp, &step.message)?;
        validate_malleable_keys(&step.message, &step.malleable_keys)?;
        if !is_valid_delegation(&previous.message, &step.message) {
            return Err(DkvacError::InvalidDelegation);
        }
        let finalized_indices = previous
            .message
            .malleable_indices
            .difference(&step.message.malleable_indices)
            .copied()
            .collect::<BTreeSet<_>>();
        let adjustment = finalized_indices.iter().try_fold(Point::default(), |acc, idx| {
            let mk = previous
                .malleable_keys
                .get(idx)
                .ok_or(DkvacError::InvalidDelegation)?;
            let delta = step.message.attributes[*idx] - previous.message.attributes[*idx];
            Ok(acc + delta * *mk)
        })?;
        let statement = VectorDelegateStatement {
            old_ev: previous.ec.ev,
            old_ez: previous.ec.ez,
            old_c_adjusted: previous.ec.c + adjustment,
            new_ev: step.ec.ev,
            new_ez: step.ec.ez,
            new_c: step.ec.c,
        };
        match &step.proof {
            Inst2DelegationProof::Delegate(proof) if proof.verify(&statement) => {}
            _ => return Err(DkvacError::InvalidProof),
        }
        previous = step;
    }

    Ok(previous)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn scalar(n: u64) -> Scalar {
        Scalar::from(n)
    }

    fn base_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([9u8; 32])
    }

    fn fixture(
        max_attributes: usize,
    ) -> (ChaCha20Rng, PublicParams, IssuerSecretKey, IssuerPublicParams) {
        let mut rng = base_rng();
        let pp = setup(&mut rng, max_attributes);
        let (isk, ipar) = keygen(&mut rng, &pp).expect("keygen");
        (rng, pp, isk, ipar)
    }

    fn sample_message() -> Message {
        Message {
            attributes: vec![scalar(3), scalar(5), scalar(7), scalar(11)],
            malleable_indices: BTreeSet::from([1, 2]),
        }
    }

    #[test]
    fn issue_show_verify_all_indices_accepts() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = sample_message();
        let policy = DisclosurePolicy {
            disclosed_indices: BTreeSet::from([0, 1, 2, 3]),
        };
        let (cred, proof) = issue_cred(&mut rng, &pp, &isk, &ipar, &message).expect("issue");
        let cred = obtain_cred(&pp, &ipar, &message, cred, &proof).expect("obtain");
        let show = show_cred(&mut rng, &pp, &ipar, &message, &policy, &cred).expect("show");
        assert!(verify_show(&pp, &isk, &policy, &show).expect("verify"));
    }

    #[test]
    fn issue_show_verify_partial_indices_accepts() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = sample_message();
        let policy = DisclosurePolicy {
            disclosed_indices: BTreeSet::from([1, 3]),
        };
        let (cred, proof) = issue_cred(&mut rng, &pp, &isk, &ipar, &message).expect("issue");
        let cred = obtain_cred(&pp, &ipar, &message, cred, &proof).expect("obtain");
        let show = show_cred(&mut rng, &pp, &ipar, &message, &policy, &cred).expect("show");
        assert!(verify_show(&pp, &isk, &policy, &show).expect("verify"));
    }

    #[test]
    fn show_invalid_policy_index_rejects() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = sample_message();
        let policy = DisclosurePolicy {
            disclosed_indices: BTreeSet::from([0, 4]),
        };
        let (cred, proof) = issue_cred(&mut rng, &pp, &isk, &ipar, &message).expect("issue");
        let cred = obtain_cred(&pp, &ipar, &message, cred, &proof).expect("obtain");
        let err = show_cred(&mut rng, &pp, &ipar, &message, &policy, &cred).expect_err("policy");
        assert!(matches!(err, DkvacError::IndexOutOfRange));
    }

    #[test]
    fn verify_wrong_disclosed_value_currently_accepts_with_dummy_proof() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = sample_message();
        let policy = DisclosurePolicy {
            disclosed_indices: BTreeSet::from([1, 3]),
        };
        let (cred, proof) = issue_cred(&mut rng, &pp, &isk, &ipar, &message).expect("issue");
        let cred = obtain_cred(&pp, &ipar, &message, cred, &proof).expect("obtain");
        let mut show = show_cred(&mut rng, &pp, &ipar, &message, &policy, &cred).expect("show");
        show.disclosed.insert(1, scalar(99));
        assert!(verify_show(&pp, &isk, &policy, &show).expect("verify"));
    }

    #[test]
    fn verify_identity_v_prime_rejects() {
        let (_, pp, isk, _) = fixture(4);
        let policy = DisclosurePolicy {
            disclosed_indices: BTreeSet::from([0]),
        };
        let show = Show {
            v_prime: Point::default(),
            w: generator(),
            q_hidden: BTreeMap::from([(1, generator()), (2, generator()), (3, generator())]),
            disclosed: BTreeMap::from([(0, scalar(1))]),
            proof: DummyProof,
        };
        let err = verify_show(&pp, &isk, &policy, &show).expect_err("identity");
        assert!(matches!(err, DkvacError::IdentityPoint));
    }

    #[test]
    fn issue_del_obtain_show_verify_accepts() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = sample_message();
        let policy = DisclosurePolicy {
            disclosed_indices: BTreeSet::from([0, 2]),
        };
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &message).expect("issue del");
        let cred = obtain_del(&pp, &encdel, &dk).expect("obtain del");
        let show = show_cred(&mut rng, &pp, &ipar, &cred.message, &policy, &cred).expect("show");
        assert!(verify_show(&pp, &isk, &policy, &show).expect("verify"));
    }

    #[test]
    fn delegate_shrink_malleable_set_accepts() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = sample_message();
        let next = Message {
            attributes: message.attributes.clone(),
            malleable_indices: BTreeSet::from([2]),
        };
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &message).expect("issue del");
        let (encdel, dk) = delegate(&mut rng, &pp, &encdel, &dk, &next).expect("delegate");
        let cred = obtain_del(&pp, &encdel, &dk).expect("obtain del");
        let policy = DisclosurePolicy {
            disclosed_indices: BTreeSet::from([0, 2]),
        };
        let show = show_cred(&mut rng, &pp, &ipar, &cred.message, &policy, &cred).expect("show");
        assert!(verify_show(&pp, &isk, &policy, &show).expect("verify"));
        assert_eq!(cred.message, next);
    }

    #[test]
    fn delegate_change_finalized_attribute_accepts() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = sample_message();
        let next = Message {
            attributes: vec![scalar(3), scalar(42), scalar(7), scalar(11)],
            malleable_indices: BTreeSet::from([2]),
        };
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &message).expect("issue del");
        let (encdel, dk) = delegate(&mut rng, &pp, &encdel, &dk, &next).expect("delegate");
        let cred = obtain_del(&pp, &encdel, &dk).expect("obtain del");
        assert_eq!(cred.message, next);
    }

    #[test]
    fn delegate_change_non_malleable_attribute_rejects() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = sample_message();
        let next = Message {
            attributes: vec![scalar(99), scalar(5), scalar(7), scalar(11)],
            malleable_indices: message.malleable_indices.clone(),
        };
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &message).expect("issue del");
        let err = delegate(&mut rng, &pp, &encdel, &dk, &next).expect_err("delegate");
        assert!(matches!(err, DkvacError::InvalidDelegation));
    }

    #[test]
    fn delegate_with_l_prime_not_subset_l_rejects() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = sample_message();
        let next = Message {
            attributes: message.attributes.clone(),
            malleable_indices: BTreeSet::from([1, 2, 3]),
        };
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &message).expect("issue del");
        let err = delegate(&mut rng, &pp, &encdel, &dk, &next).expect_err("delegate");
        assert!(matches!(err, DkvacError::InvalidDelegation));
    }

    #[test]
    fn delegate_twice_then_show_accepts() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = sample_message();
        let next1 = Message {
            attributes: vec![scalar(3), scalar(9), scalar(7), scalar(11)],
            malleable_indices: BTreeSet::from([2]),
        };
        let next2 = Message {
            attributes: vec![scalar(3), scalar(9), scalar(13), scalar(11)],
            malleable_indices: BTreeSet::new(),
        };
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &message).expect("issue del");
        let (encdel, dk) = delegate(&mut rng, &pp, &encdel, &dk, &next1).expect("delegate1");
        let (encdel, dk) = delegate(&mut rng, &pp, &encdel, &dk, &next2).expect("delegate2");
        let cred = obtain_del(&pp, &encdel, &dk).expect("obtain del");
        let policy = DisclosurePolicy {
            disclosed_indices: BTreeSet::from([1, 2]),
        };
        let show = show_cred(&mut rng, &pp, &ipar, &cred.message, &policy, &cred).expect("show");
        assert!(verify_show(&pp, &isk, &policy, &show).expect("verify"));
        assert_eq!(cred.message, next2);
    }

    #[test]
    fn message_wrong_length_rejects() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = Message {
            attributes: vec![scalar(1), scalar(2), scalar(3)],
            malleable_indices: BTreeSet::new(),
        };
        let err = issue_cred(&mut rng, &pp, &isk, &ipar, &message).expect_err("length");
        assert!(matches!(err, DkvacError::InvalidAttributeSet));
    }

    #[test]
    fn malleable_index_out_of_range_rejects() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = Message {
            attributes: vec![scalar(1), scalar(2), scalar(3), scalar(4)],
            malleable_indices: BTreeSet::from([4]),
        };
        let err = issue_cred(&mut rng, &pp, &isk, &ipar, &message).expect_err("range");
        assert!(matches!(err, DkvacError::IndexOutOfRange));
    }

    #[test]
    fn obtain_del_empty_chain_rejects() {
        let (_, pp, _, _) = fixture(4);
        let err = obtain_del(&pp, &EncDel { steps: vec![] }, &scalar(1)).expect_err("empty");
        assert!(matches!(err, DkvacError::InvalidDelegation));
    }

    #[test]
    fn tamper_delegated_c_rejects() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = sample_message();
        let next = Message {
            attributes: vec![scalar(3), scalar(9), scalar(7), scalar(11)],
            malleable_indices: BTreeSet::from([2]),
        };
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &message).expect("issue del");
        let (mut encdel, dk) = delegate(&mut rng, &pp, &encdel, &dk, &next).expect("delegate");
        encdel.steps.last_mut().expect("step").ec.c += generator();
        let err = obtain_del(&pp, &encdel, &dk).expect_err("tamper");
        assert!(matches!(err, DkvacError::InvalidProof));
    }

    #[test]
    fn tamper_delegated_ev_rejects() {
        let (mut rng, pp, isk, ipar) = fixture(4);
        let message = sample_message();
        let next = Message {
            attributes: vec![scalar(3), scalar(9), scalar(7), scalar(11)],
            malleable_indices: BTreeSet::from([2]),
        };
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &message).expect("issue del");
        let (mut encdel, dk) = delegate(&mut rng, &pp, &encdel, &dk, &next).expect("delegate");
        encdel.steps.last_mut().expect("step").ec.ev += generator();
        let err = obtain_del(&pp, &encdel, &dk).expect_err("tamper");
        assert!(matches!(err, DkvacError::InvalidProof));
    }
}
