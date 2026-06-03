use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar as DalekScalar;
use curve25519_dalek::traits::Identity;
use rand_core::{CryptoRng, RngCore};

pub type Scalar = DalekScalar;
pub type Point = RistrettoPoint;

pub fn generator() -> Point {
    RISTRETTO_BASEPOINT_POINT
}

pub fn derive_h<R: CryptoRng + RngCore>(rng: &mut R) -> Point {
    loop {
        let h = Point::random(rng);
        if !is_identity(&h) {
            return h;
        }
    }
}

pub fn random_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Scalar {
    loop {
        let scalar = Scalar::random(rng);
        if scalar != Scalar::ZERO {
            return scalar;
        }
    }
}

pub fn is_identity(p: &Point) -> bool {
    *p == Point::identity()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn derive_h_is_deterministic_for_seeded_rng() {
        let mut rng1 = ChaCha20Rng::from_seed([9u8; 32]);
        let mut rng2 = ChaCha20Rng::from_seed([9u8; 32]);
        assert_eq!(derive_h(&mut rng1), derive_h(&mut rng2));
    }

    #[test]
    fn derive_h_is_not_identity() {
        let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
        assert!(!is_identity(&derive_h(&mut rng)));
    }

    #[test]
    fn random_scalar_is_nonzero() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        assert_ne!(random_scalar(&mut rng), Scalar::ZERO);
    }
}
