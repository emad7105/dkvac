use crate::error::DkvacError;
use crate::group::{Point, Scalar, derive_h, generator, is_identity, random_scalar};
use crate::zk::{
    SubsetDelegatableIssueProof, SubsetDelegatableIssueStatement, SubsetDelegatableIssueWitness,
    SubsetDelegateProof, SubsetDelegateStatement, SubsetDelegateWitness, SubsetDirectIssueProof,
    SubsetDirectIssueStatement, SubsetDirectIssueWitness,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScalarBytes(pub [u8; 32]);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicParams {
    pub g: Point,
    pub h: Point,
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct IssuerSecretKey {
    pub x: Scalar,
    pub y: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerPublicParams {
    pub x_g: Point,
    pub y_g: Point,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    pub v_x_g: Point,
    pub ev: Point,
    pub components: BTreeMap<ScalarBytes, Point>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedCredential {
    pub e: Point,
    pub ev: Point,
    pub ez: Point,
    pub components: BTreeMap<ScalarBytes, Point>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegationStep {
    pub ec: EncryptedCredential,
    pub attributes: BTreeSet<ScalarBytes>,
    pub proof: Inst1DelegationProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncDel {
    pub steps: Vec<DelegationStep>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Show {
    pub v_prime: Point,
    pub c_prime: Point,
    pub disclosed: Vec<Scalar>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Inst1DelegationProof {
    Issue(SubsetDelegatableIssueProof),
    Delegate(SubsetDelegateProof),
}

pub fn scalar_to_key(s: &Scalar) -> ScalarBytes {
    ScalarBytes(s.to_bytes())
}

pub fn setup<R: CryptoRng + RngCore>(rng: &mut R) -> PublicParams {
    PublicParams {
        g: generator(),
        h: derive_h(rng),
    }
}

pub fn keygen<R: CryptoRng + RngCore>(
    rng: &mut R,
    pp: &PublicParams,
) -> Result<(IssuerSecretKey, IssuerPublicParams), DkvacError> {
    if is_identity(&pp.g) || is_identity(&pp.h) {
        return Err(DkvacError::IdentityPoint);
    }

    let x = random_scalar(rng);
    let y = random_scalar(rng);
    let isk = IssuerSecretKey { x, y };
    let ipar = IssuerPublicParams {
        x_g: isk.x * pp.g,
        y_g: isk.y * pp.g,
    };
    Ok((isk, ipar))
}

pub fn issue_cred<R: CryptoRng + RngCore>(
    rng: &mut R,
    pp: &PublicParams,
    isk: &IssuerSecretKey,
    ipar: &IssuerPublicParams,
    attributes: &[Scalar],
) -> Result<(Credential, SubsetDirectIssueProof), DkvacError> {
    let attribute_set = collect_attribute_set(attributes)?;
    validate_issue_attributes(isk, &attribute_set)?;

    let v = random_scalar(rng);
    let v_g = v * pp.g;
    let v_x_g = v * ipar.x_g;
    let components = compute_components(&attribute_set, isk, &v_g)?;
    let cred = Credential {
        v_x_g,
        ev: v_g,
        components,
    };
    let proof = SubsetDirectIssueProof::prove(
        rng,
        &SubsetDirectIssueStatement {
            g: pp.g,
            x_g: ipar.x_g,
            y_g: ipar.y_g,
            v_x_g: cred.v_x_g,
            ev: cred.ev,
            components: cred.components.clone(),
        },
        &SubsetDirectIssueWitness {
            x: isk.x,
            y: isk.y,
            v,
        },
    );
    Ok((cred, proof))
}

pub fn obtain_cred(
    ipar: &IssuerPublicParams,
    attributes: &[Scalar],
    cred: Credential,
    proof: &SubsetDirectIssueProof,
) -> Result<Credential, DkvacError> {
    let statement = SubsetDirectIssueStatement {
        g: generator(),
        x_g: ipar.x_g,
        y_g: ipar.y_g,
        v_x_g: cred.v_x_g,
        ev: cred.ev,
        components: cred.components.clone(),
    };
    if !proof.verify(&statement) {
        return Err(DkvacError::InvalidProof);
    }

    let attribute_set = collect_attribute_set(attributes)?;
    if cred.components.len() != attribute_set.len() {
        return Err(DkvacError::InvalidAttributeSet);
    }

    for key in attribute_set {
        if !cred.components.contains_key(&key) {
            return Err(DkvacError::InvalidAttributeSet);
        }
    }

    Ok(cred)
}

pub fn show_cred<R: CryptoRng + RngCore>(
    rng: &mut R,
    cred: &Credential,
    disclosed: &[Scalar],
) -> Result<Show, DkvacError> {
    let disclosed_set = collect_disclosed_subset(disclosed)?;
    ensure_components_present(&cred.components, &disclosed_set)?;

    let mu = random_scalar(rng);
    let sum_c = disclosed_set
        .iter()
        .map(|key| cred.components.get(key).copied().expect("validated component"))
        .fold(Point::default(), |acc, point| acc + point);

    Ok(Show {
        v_prime: mu * cred.v_x_g,
        c_prime: mu * sum_c,
        disclosed: disclosed.to_vec(),
    })
}

pub fn verify_show(isk: &IssuerSecretKey, show: &Show) -> Result<bool, DkvacError> {
    if show.disclosed.is_empty() {
        return Err(DkvacError::InvalidDisclosure);
    }
    if has_duplicate_attributes(show.disclosed.iter()) {
        return Err(DkvacError::InvalidDisclosure);
    }
    if is_identity(&show.c_prime) {
        return Err(DkvacError::IdentityPoint);
    }

    let mut aggregate = Scalar::ZERO;
    for attribute in &show.disclosed {
        let denom = isk.y + attribute;
        if denom == Scalar::ZERO {
            return Err(DkvacError::InvalidDisclosure);
        }
        aggregate += denom.invert();
    }

    Ok(aggregate * show.v_prime == isk.x * show.c_prime)
}

pub fn issue_del<R: CryptoRng + RngCore>(
    rng: &mut R,
    pp: &PublicParams,
    isk: &IssuerSecretKey,
    ipar: &IssuerPublicParams,
    attributes: &[Scalar],
) -> Result<(EncDel, Scalar), DkvacError> {
    let attribute_set = collect_attribute_set(attributes)?;
    validate_issue_attributes(isk, &attribute_set)?;

    let v = random_scalar(rng);
    let z = random_scalar(rng);
    let v_g = v * pp.g;
    let e = v * ipar.x_g + z * pp.h;
    let ev = v_g;
    let ez = z * pp.g;
    let components = compute_components(&attribute_set, isk, &v_g)?;
    let proof_components = components.clone();
    let step = DelegationStep {
        ec: EncryptedCredential {
            e,
            ev,
            ez,
            components,
        },
        attributes: attribute_set,
        proof: Inst1DelegationProof::Issue(SubsetDelegatableIssueProof::prove(
            rng,
            &SubsetDelegatableIssueStatement {
                g: pp.g,
                h: pp.h,
                x_g: ipar.x_g,
                y_g: ipar.y_g,
                e,
                ev,
                ez,
                components: proof_components,
            },
            &SubsetDelegatableIssueWitness {
                x: isk.x,
                y: isk.y,
                v,
                z,
            },
        )),
    };

    Ok((EncDel { steps: vec![step] }, z))
}

pub fn delegate<R: CryptoRng + RngCore>(
    rng: &mut R,
    encdel: &EncDel,
    dk: &Scalar,
    delegated_attributes: &[Scalar],
) -> Result<(EncDel, Scalar), DkvacError> {
    let current = encdel.steps.last().ok_or(DkvacError::InvalidDelegation)?;
    // validate_step(current)?;

    let delegated_set = collect_attribute_set(delegated_attributes)?;
    if delegated_set.is_empty() {
        return Err(DkvacError::InvalidDelegation);
    }
    if !delegated_set.is_subset(&current.attributes) {
        return Err(DkvacError::InvalidDelegation);
    }

    let mu = random_scalar(rng);
    let components = delegated_set
        .iter()
        .map(|key| {
            let component = current
                .ec
                .components
                .get(key)
                .ok_or(DkvacError::InvalidDelegation)?;
            Ok((*key, mu * *component))
        })
        .collect::<Result<BTreeMap<_, _>, DkvacError>>()?;

    let new_ec = EncryptedCredential {
        e: mu * current.ec.e,
        ev: mu * current.ec.ev,
        ez: mu * current.ec.ez,
        components,
    };
    let old_components = current
        .ec
        .components
        .iter()
        .filter(|(key, _)| delegated_set.contains(*key))
        .map(|(key, point)| (*key, *point))
        .collect();
    let statement = SubsetDelegateStatement {
        old_e: current.ec.e,
        old_ev: current.ec.ev,
        old_ez: current.ec.ez,
        old_components,
        new_e: new_ec.e,
        new_ev: new_ec.ev,
        new_ez: new_ec.ez,
        new_components: new_ec.components.clone(),
    };

    let next_step = DelegationStep {
        ec: new_ec,
        attributes: delegated_set,
        proof: Inst1DelegationProof::Delegate(SubsetDelegateProof::prove(
            rng,
            &statement,
            &SubsetDelegateWitness { mu },
        )),
    };

    let mut steps = encdel.steps.clone();
    steps.push(next_step);
    Ok((EncDel { steps }, mu * *dk))
}

pub fn obtain_del(
    pp: &PublicParams,
    ipar: &IssuerPublicParams,
    encdel: &EncDel,
    dk: &Scalar,
) -> Result<Credential, DkvacError> {
    let final_step = validate_encdel(pp, ipar, encdel)?;
    let v_x_g = final_step.ec.e - *dk * pp.h;

    Ok(Credential {
        v_x_g,
        ev: final_step.ec.ev,
        components: final_step.ec.components.clone(),
    })
}

fn collect_attribute_set(attributes: &[Scalar]) -> Result<BTreeSet<ScalarBytes>, DkvacError> {
    if attributes.is_empty() {
        return Err(DkvacError::InvalidAttributeSet);
    }

    let set = attributes.iter().map(scalar_to_key).collect::<BTreeSet<_>>();
    if set.len() != attributes.len() {
        return Err(DkvacError::InvalidAttributeSet);
    }

    Ok(set)
}

fn collect_disclosed_subset(disclosed: &[Scalar]) -> Result<BTreeSet<ScalarBytes>, DkvacError> {
    if disclosed.is_empty() {
        return Err(DkvacError::InvalidDisclosure);
    }

    let set = disclosed.iter().map(scalar_to_key).collect::<BTreeSet<_>>();
    if set.len() != disclosed.len() {
        return Err(DkvacError::InvalidDisclosure);
    }

    Ok(set)
}

fn validate_issue_attributes(
    isk: &IssuerSecretKey,
    attributes: &BTreeSet<ScalarBytes>,
) -> Result<(), DkvacError> {
    for key in attributes {
        let scalar = key_to_scalar(key)?;
        if isk.y + scalar == Scalar::ZERO {
            return Err(DkvacError::InvalidAttributeSet);
        }
    }
    Ok(())
}

fn compute_components(
    attributes: &BTreeSet<ScalarBytes>,
    isk: &IssuerSecretKey,
    v_g: &Point,
) -> Result<BTreeMap<ScalarBytes, Point>, DkvacError> {
    attributes
        .iter()
        .map(|key| {
            let scalar = key_to_scalar(key)?;
            let denom = isk.y + scalar;
            if denom == Scalar::ZERO {
                return Err(DkvacError::InvalidAttributeSet);
            }
            Ok((*key, denom.invert() * *v_g))
        })
        .collect()
}

fn ensure_components_present(
    components: &BTreeMap<ScalarBytes, Point>,
    disclosed: &BTreeSet<ScalarBytes>,
) -> Result<(), DkvacError> {
    for key in disclosed {
        if !components.contains_key(key) {
            return Err(DkvacError::InvalidDisclosure);
        }
    }
    Ok(())
}

fn validate_encdel<'a>(
    pp: &PublicParams,
    ipar: &IssuerPublicParams,
    encdel: &'a EncDel,
) -> Result<&'a DelegationStep, DkvacError> {
    let mut steps = encdel.steps.iter();
    let first = steps.next().ok_or(DkvacError::InvalidDelegation)?;
    match &first.proof {
        Inst1DelegationProof::Issue(proof)
            if proof.verify(&SubsetDelegatableIssueStatement {
                g: pp.g,
                h: pp.h,
                x_g: ipar.x_g,
                y_g: ipar.y_g,
                e: first.ec.e,
                ev: first.ec.ev,
                ez: first.ec.ez,
                components: first.ec.components.clone(),
            }) => {}
        _ => return Err(DkvacError::InvalidProof),
    }
    validate_step_structure(first)?;

    let mut previous = first;
    for step in steps {
        validate_step_structure(step)?;
        if !step.attributes.is_subset(&previous.attributes) {
            return Err(DkvacError::InvalidDelegation);
        }
        let statement = SubsetDelegateStatement {
            old_e: previous.ec.e,
            old_ev: previous.ec.ev,
            old_ez: previous.ec.ez,
            old_components: previous
                .ec
                .components
                .iter()
                .filter(|(key, _)| step.attributes.contains(*key))
                .map(|(key, point)| (*key, *point))
                .collect(),
            new_e: step.ec.e,
            new_ev: step.ec.ev,
            new_ez: step.ec.ez,
            new_components: step.ec.components.clone(),
        };
        match &step.proof {
            Inst1DelegationProof::Delegate(proof) if proof.verify(&statement) => {}
            _ => return Err(DkvacError::InvalidProof),
        }
        previous = step;
    }

    Ok(previous)
}

fn validate_step_structure(step: &DelegationStep) -> Result<(), DkvacError> {
    if step.attributes.is_empty() {
        return Err(DkvacError::InvalidDelegation);
    }
    if step.attributes.len() != step.ec.components.len() {
        return Err(DkvacError::InvalidDelegation);
    }
    for key in &step.attributes {
        if !step.ec.components.contains_key(key) {
            return Err(DkvacError::InvalidDelegation);
        }
    }
    Ok(())
}

fn key_to_scalar(key: &ScalarBytes) -> Result<Scalar, DkvacError> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(key.0))
        .ok_or(DkvacError::InvalidAttributeSet)
}


fn has_duplicate_attributes<'a, I>(attributes: I) -> bool
where
    I: IntoIterator<Item = &'a Scalar>,
{
    let mut seen = BTreeSet::new();
    for attribute in attributes {
        if !seen.insert(scalar_to_key(attribute)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn scalar(n: u64) -> Scalar {
        Scalar::from(n)
    }

    fn setup_issuer(seed: u8) -> (ChaCha20Rng, PublicParams, IssuerSecretKey, IssuerPublicParams) {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let pp = setup(&mut rng);
        let (isk, ipar) = keygen(&mut rng, &pp).expect("keygen");
        (rng, pp, isk, ipar)
    }

    #[test]
    fn issue_show_verify_full_set_accepts() {
        let (mut rng, pp, isk, ipar) = setup_issuer(1);
        let attrs = vec![scalar(3), scalar(5), scalar(8)];
        let (cred, proof) = issue_cred(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue");
        let cred = obtain_cred(&ipar, &attrs, cred, &proof).expect("obtain");
        let show = show_cred(&mut rng, &cred, &attrs).expect("show");
        assert!(verify_show(&isk, &show).expect("verify"));
    }

    #[test]
    fn issue_show_verify_subset_accepts() {
        let (mut rng, pp, isk, ipar) = setup_issuer(2);
        let attrs = vec![scalar(2), scalar(4), scalar(6)];
        let disclosed = vec![scalar(2), scalar(6)];
        let (cred, proof) = issue_cred(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue");
        let cred = obtain_cred(&ipar, &attrs, cred, &proof).expect("obtain");
        let show = show_cred(&mut rng, &cred, &disclosed).expect("show");
        assert!(verify_show(&isk, &show).expect("verify"));
    }

    #[test]
    fn obtain_cred_rejects_modified_v_x_g() {
        let (mut rng, pp, isk, ipar) = setup_issuer(21);
        let attrs = vec![scalar(2), scalar(4), scalar(6)];
        let (mut cred, proof) = issue_cred(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue");
        cred.v_x_g += generator();
        let err = obtain_cred(&ipar, &attrs, cred, &proof).expect_err("obtain");
        assert!(matches!(err, DkvacError::InvalidProof));
    }

    #[test]
    fn obtain_cred_rejects_modified_component() {
        let (mut rng, pp, isk, ipar) = setup_issuer(22);
        let attrs = vec![scalar(3), scalar(5), scalar(8)];
        let (mut cred, proof) = issue_cred(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue");
        let key = scalar_to_key(&scalar(3));
        *cred.components.get_mut(&key).expect("component") += generator();
        let err = obtain_cred(&ipar, &attrs, cred, &proof).expect_err("obtain");
        assert!(matches!(err, DkvacError::InvalidProof));
    }

    #[test]
    fn show_attribute_not_in_credential_rejects() {
        let (mut rng, pp, isk, ipar) = setup_issuer(3);
        let attrs = vec![scalar(7), scalar(9)];
        let (cred, proof) = issue_cred(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue");
        let cred = obtain_cred(&ipar, &attrs, cred, &proof).expect("obtain");
        let err = show_cred(&mut rng, &cred, &[scalar(7), scalar(11)]).expect_err("missing");
        assert!(matches!(err, DkvacError::InvalidDisclosure));
    }

    #[test]
    fn verify_wrong_disclosed_attribute_rejects() {
        let (mut rng, pp, isk, ipar) = setup_issuer(4);
        let attrs = vec![scalar(10), scalar(12), scalar(14)];
        let disclosed = vec![scalar(10), scalar(14)];
        let (cred, proof) = issue_cred(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue");
        let cred = obtain_cred(&ipar, &attrs, cred, &proof).expect("obtain");
        let mut show = show_cred(&mut rng, &cred, &disclosed).expect("show");
        show.disclosed = vec![scalar(10), scalar(12)];
        assert!(!verify_show(&isk, &show).expect("verify"));
    }

    #[test]
    fn verify_identity_c_prime_rejects() {
        let (_, _, isk, _) = setup_issuer(5);
        let show = Show {
            v_prime: generator(),
            c_prime: Point::default(),
            disclosed: vec![scalar(1)],
        };
        let err = verify_show(&isk, &show).expect_err("identity");
        assert!(matches!(err, DkvacError::IdentityPoint));
    }

    #[test]
    fn issue_del_obtain_show_verify_accepts() {
        let (mut rng, pp, isk, ipar) = setup_issuer(6);
        let attrs = vec![scalar(1), scalar(2), scalar(3)];
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue del");
        let cred = obtain_del(&pp, &ipar, &encdel, &dk).expect("obtain del");
        let show = show_cred(&mut rng, &cred, &[scalar(1), scalar(3)]).expect("show");
        assert!(verify_show(&isk, &show).expect("verify"));
    }

    #[test]
    fn tamper_initial_encrypted_e_rejects() {
        let (mut rng, pp, isk, ipar) = setup_issuer(23);
        let attrs = vec![scalar(1), scalar(2), scalar(3)];
        let (mut encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue del");
        encdel.steps[0].ec.e += generator();
        let err = obtain_del(&pp, &ipar, &encdel, &dk).expect_err("tamper");
        assert!(matches!(err, DkvacError::InvalidProof));
    }

    #[test]
    fn tamper_initial_encrypted_component_rejects() {
        let (mut rng, pp, isk, ipar) = setup_issuer(24);
        let attrs = vec![scalar(4), scalar(5), scalar(6)];
        let (mut encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue del");
        let key = scalar_to_key(&scalar(4));
        *encdel.steps[0]
            .ec
            .components
            .get_mut(&key)
            .expect("component") += generator();
        let err = obtain_del(&pp, &ipar, &encdel, &dk).expect_err("tamper");
        assert!(matches!(err, DkvacError::InvalidProof));
    }

    #[test]
    fn delegate_subset_obtain_show_verify_accepts() {
        let (mut rng, pp, isk, ipar) = setup_issuer(7);
        let attrs = vec![scalar(4), scalar(5), scalar(6)];
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue del");
        let subset = vec![scalar(4), scalar(6)];
        let (encdel, dk) = delegate(&mut rng, &encdel, &dk, &subset).expect("delegate");
        let cred = obtain_del(&pp, &ipar, &encdel, &dk).expect("obtain del");
        let show = show_cred(&mut rng, &cred, &subset).expect("show");
        assert!(verify_show(&isk, &show).expect("verify"));
    }

    #[test]
    fn delegate_twice_then_show_accepts() {
        let (mut rng, pp, isk, ipar) = setup_issuer(8);
        let attrs = vec![scalar(11), scalar(12), scalar(13), scalar(14)];
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue del");
        let (encdel, dk) =
            delegate(&mut rng, &encdel, &dk, &[scalar(11), scalar(13), scalar(14)]).expect("d1");
        let (encdel, dk) =
            delegate(&mut rng, &encdel, &dk, &[scalar(11), scalar(14)]).expect("d2");
        let cred = obtain_del(&pp, &ipar, &encdel, &dk).expect("obtain del");
        let show = show_cred(&mut rng, &cred, &[scalar(14)]).expect("show");
        assert!(verify_show(&isk, &show).expect("verify"));
    }

    #[test]
    fn delegate_to_non_subset_rejects() {
        let (mut rng, pp, isk, ipar) = setup_issuer(9);
        let attrs = vec![scalar(20), scalar(21)];
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue del");
        let err = delegate(&mut rng, &encdel, &dk, &[scalar(20), scalar(22)]).expect_err("subset");
        assert!(matches!(err, DkvacError::InvalidDelegation));
    }

    #[test]
    fn delegated_removed_attribute_cannot_be_shown() {
        let (mut rng, pp, isk, ipar) = setup_issuer(10);
        let attrs = vec![scalar(30), scalar(31), scalar(32)];
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue del");
        let (encdel, dk) = delegate(&mut rng, &encdel, &dk, &[scalar(30), scalar(32)]).expect("d1");
        let cred = obtain_del(&pp, &ipar, &encdel, &dk).expect("obtain del");
        let err = show_cred(&mut rng, &cred, &[scalar(31)]).expect_err("removed");
        assert!(matches!(err, DkvacError::InvalidDisclosure));
        let show = show_cred(&mut rng, &cred, &[scalar(30)]).expect("show");
        assert!(verify_show(&isk, &show).expect("verify"));
    }

    #[test]
    fn tamper_delegated_step_e_rejects() {
        let (mut rng, pp, isk, ipar) = setup_issuer(11);
        let attrs = vec![scalar(1), scalar(2), scalar(3)];
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue del");
        let (mut encdel, dk) = delegate(&mut rng, &encdel, &dk, &[scalar(1), scalar(3)]).expect("delegate");
        encdel.steps.last_mut().expect("step").ec.e += generator();
        let err = obtain_del(&pp, &ipar, &encdel, &dk).expect_err("tamper");
        assert!(matches!(err, DkvacError::InvalidProof));
    }

    #[test]
    fn tamper_delegated_component_rejects() {
        let (mut rng, pp, isk, ipar) = setup_issuer(12);
        let attrs = vec![scalar(4), scalar(5), scalar(6)];
        let (encdel, dk) = issue_del(&mut rng, &pp, &isk, &ipar, &attrs).expect("issue del");
        let (mut encdel, dk) = delegate(&mut rng, &encdel, &dk, &[scalar(4), scalar(6)]).expect("delegate");
        let key = scalar_to_key(&scalar(4));
        *encdel
            .steps
            .last_mut()
            .expect("step")
            .ec
            .components
            .get_mut(&key)
            .expect("component") += generator();
        let err = obtain_del(&pp, &ipar, &encdel, &dk).expect_err("tamper");
        assert!(matches!(err, DkvacError::InvalidProof));
    }
}
