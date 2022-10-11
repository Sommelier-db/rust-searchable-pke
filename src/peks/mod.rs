use crate::hashes::*;
use fff::Field;
use groupy::{CurveAffine, CurveProjective};
use paired::Engine;
use rand_core::RngCore;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PEKSError {
    #[error(transparent)]
    ECHashError(#[from] ECHashError),
}

#[derive(Debug, Clone)]
pub struct SecretKey<E: Engine> {
    alpha: E::Fr,
}

#[derive(Debug, Clone)]
pub struct PublicKey<E: Engine> {
    g: E::G2Affine,
    h: E::G2Affine,
}

#[derive(Debug, Clone)]
pub struct Ciphertext<E: Engine> {
    a: E::G2Affine,
    b: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Trapdoor<E: Engine> {
    t: E::G1Affine,
}

impl<E: Engine> SecretKey<E> {
    pub fn gen<R: RngCore>(rng: &mut R) -> Self {
        let alpha = <E::Fr as Field>::random(rng);
        Self { alpha }
    }

    pub fn into_public_key<R: RngCore>(&self, rng: &mut R) -> PublicKey<E> {
        let g = <E::G2 as CurveProjective>::random(rng).into_affine();
        let h = g.mul(self.alpha).into_affine();
        PublicKey { g, h }
    }

    pub fn gen_trapdoor(&self, keyword: &[u8]) -> Trapdoor<E> {
        let hashed_w = hash_bytes2point::<E>(keyword).into_affine();
        let t = hashed_w.mul(self.alpha).into_affine();
        Trapdoor { t }
    }
}

impl<E: Engine> PublicKey<E> {
    pub fn from_secret_key<R: RngCore>(secret_key: &SecretKey<E>, rng: &mut R) -> Self {
        secret_key.into_public_key(rng)
    }

    pub fn encrypt<R: RngCore>(
        &self,
        keyword: &[u8],
        rng: &mut R,
    ) -> Result<Ciphertext<E>, PEKSError> {
        let r = <E::Fr as Field>::random(rng);
        let a = self.g.mul(r);
        let hashed_w = hash_bytes2point::<E>(keyword);
        let hr = self.h.mul(r);
        let pairinged = E::pairing(hashed_w, hr);
        let b = hash_field2bytes::<E>(pairinged)?;
        let a = a.into_affine();
        Ok(Ciphertext { a, b })
    }
}

impl<E: Engine> Trapdoor<E> {
    pub fn test(&self, ct: &Ciphertext<E>) -> Result<bool, PEKSError> {
        let pairinged = E::pairing(self.t.into_projective(), ct.a.into_projective());
        let hashed = hash_field2bytes::<E>(pairinged)?;
        Ok(hashed == ct.b)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use paired::bls12_381::Bls12;
    use rand::{thread_rng, Rng};
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_peks_valid_case() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let secret_key = SecretKey::<Bls12>::gen(&mut rng);
        let public_key = secret_key.into_public_key(&mut rng);
        let mut thread_rng = thread_rng();
        let mut keyword1 = [0; 32];
        let mut keyword2 = [1; 32];
        for i in 0..32 {
            keyword1[i] = thread_rng.gen();
            keyword2[i] = thread_rng.gen();
        }
        let ct1 = public_key.encrypt(&keyword1, &mut rng).unwrap();
        let ct2 = public_key.encrypt(&keyword2, &mut rng).unwrap();
        let trapdoor = secret_key.gen_trapdoor(&keyword1);
        assert_eq!(trapdoor.test(&ct1).unwrap(), true);
        assert_eq!(trapdoor.test(&ct2).unwrap(), false);
    }
}
