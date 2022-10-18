mod c_api;
use crate::utils::polynomial_from_roots;
use crate::{hashes::*, BaseROFr};
pub use c_api::*;
use fff::{Field, PrimeField};
use groupy::{CurveAffine, CurveProjective};
use paired::{Engine, PairingCurveAffine};
use rand::seq::SliceRandom;
use rand_core::RngCore;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PECDKError<E: Engine> {
    #[error("Fail to compute the inversed Fr value `{0}`")]
    InverseFrError(E::Fr),
    #[error("Fail to compute the inversed Fqk value `{0}`")]
    InverseFqkError(E::Fqk),
    #[error(transparent)]
    ECHashError(#[from] ECHashError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKey<E: Engine> {
    alphas: Vec<E::Fr>,
    betas: Vec<E::Fr>,
    theta: E::Fr,
    g1: E::G1Affine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey<E: Engine> {
    g2: E::G2Affine,
    x_points: Vec<E::G2Affine>,
    y_points: Vec<E::G2Affine>,
    z_point: E::G2Affine,
    mue: E::Fqk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct Ciphertext<E: Engine> {
    a_points: Vec<Vec<E::G2Affine>>,
    b_points: Vec<Vec<E::G2Affine>>,
    c_points: Vec<E::G2Affine>,
    d_bytes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct Trapdoor<E: Engine> {
    t1s: Vec<E::G1Affine>,
    t2s: Vec<E::G1Affine>,
    t3: E::Fr,
    sym: SearchSym,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SearchSym {
    AND,
    OR,
}

const TAG: &'static str = "pecdk_hash_to_field";

impl<E: Engine> SecretKey<E> {
    pub fn gen<R: RngCore>(rng: &mut R, num_keyword: usize) -> Self {
        let n = num_keyword;
        let alphas = (0..n + 1)
            .map(|_| <E::Fr as Field>::random(rng))
            .collect::<Vec<E::Fr>>();
        let betas = (0..n + 1)
            .map(|_| <E::Fr as Field>::random(rng))
            .collect::<Vec<E::Fr>>();
        let theta = <E::Fr as Field>::random(rng);
        let g1 = <E::G1 as CurveProjective>::random(rng).into_affine();
        Self {
            alphas,
            betas,
            theta,
            g1,
        }
    }

    pub fn into_public_key<R: RngCore>(&self, rng: &mut R) -> PublicKey<E> {
        let g2 = <E::G2 as CurveProjective>::random(rng).into_affine();
        let x_points = self
            .alphas
            .clone()
            .into_iter()
            .map(|s: E::Fr| g2.mul(s).into_affine())
            .collect::<Vec<E::G2Affine>>();
        let y_points = self
            .betas
            .clone()
            .into_iter()
            .map(|s: E::Fr| g2.mul(s).into_affine())
            .collect::<Vec<E::G2Affine>>();
        let z_point = g2.mul(self.theta).into_affine();
        let mue = E::pairing(self.g1.into_projective(), g2.into_projective());
        PublicKey {
            g2,
            x_points,
            y_points,
            z_point,
            mue,
        }
    }

    pub fn gen_trapdoor<R: RngCore, F: BaseROFr<E>>(
        &self,
        keywords: Vec<Vec<u8>>,
        sym: SearchSym,
        rng: &mut R,
    ) -> Result<Trapdoor<E>, PECDKError<E>> {
        let m = keywords.len();
        let zero = <E::Fr as Field>::zero();
        let one = <E::Fr as Field>::one();
        let mut minus_one = zero.clone();
        minus_one.sub_assign(&one);

        let mut keywords = keywords;
        keywords.shuffle(rng);

        let hashes = keywords
            .into_par_iter()
            .map(|word| hash_bytes2field::<F, E>(&word, TAG.as_bytes()))
            .collect::<Result<Vec<E::Fr>, ECHashError>>()?;

        let coefficients = polynomial_from_roots(&hashes);

        let u = <E::Fr as Field>::random(rng);
        let mut denominator = zero.clone();
        for i in 0..(m + 1) {
            let mut val = u.clone();
            val.mul_assign(&self.theta);
            val.add_assign(&self.alphas[i]);
            val.mul_assign(&coefficients[i]);
            denominator.add_assign(&val);
        }
        denominator = denominator
            .inverse()
            .ok_or(PECDKError::InverseFrError(denominator))?;

        let beta_invs = (0..m + 1)
            .into_par_iter()
            .map(|i| {
                self.betas[i]
                    .inverse()
                    .ok_or(PECDKError::InverseFrError(self.betas[i]))
            })
            .collect::<Result<Vec<E::Fr>, PECDKError<E>>>()?;

        let t1s = (0..m + 1)
            .into_par_iter()
            .map(|i| {
                let mut scalar = coefficients[i].clone();
                scalar.mul_assign(&denominator);
                self.g1.mul(scalar).into_affine()
            })
            .collect::<Vec<E::G1Affine>>();
        let t2s = t1s
            .par_iter()
            .enumerate()
            .map(|(i, t1)| t1.mul(beta_invs[i]).into_affine())
            .collect();
        let t3 = u;
        Ok(Trapdoor { t1s, t2s, t3, sym })
    }
}

impl<E: Engine> PublicKey<E> {
    pub fn num_keyword(&self) -> usize {
        self.x_points.len() - 1
    }

    pub fn from_secret_key<R: RngCore>(secret_key: &SecretKey<E>, rng: &mut R) -> Self {
        secret_key.into_public_key(rng)
    }

    pub fn encrypt<R: RngCore, F: BaseROFr<E>>(
        &self,
        keywords: Vec<Vec<u8>>,
        rng: &mut R,
    ) -> Result<Ciphertext<E>, PECDKError<E>> {
        let n = self.x_points.len() - 1;
        assert_eq!(keywords.len(), n);
        let mut keywords = keywords;
        keywords.shuffle(rng);

        let rs = (0..n)
            .map(|_| <E::Fr as Field>::random(rng))
            .collect::<Vec<E::Fr>>();
        let mut uss = Vec::with_capacity(n);
        for _ in 0..n {
            let us = (0..n + 1)
                .map(|_| <E::Fr as Field>::random(rng))
                .collect::<Vec<E::Fr>>();
            uss.push(us);
        }
        let mut a_points = Vec::with_capacity(n);
        let mut b_points = Vec::with_capacity(n);
        let tag = TAG.as_bytes();
        for i in 0..n {
            let r: E::Fr = rs[i];
            let hashed_word = hash_bytes2field::<F, E>(&keywords[i], tag)?;
            let a_point_vec = (0..n + 1)
                .into_par_iter()
                .map(|j| {
                    let mut xr = self.x_points[j].mul(r.clone());
                    let mut rh_u = r;
                    rh_u.mul_assign(&hashed_word.pow(&vec![j as u64]));
                    rh_u.add_assign(&uss[i][j]);
                    let g_point = self.g2.mul(rh_u);
                    xr.add_assign(&g_point);
                    xr.into_affine()
                })
                .collect::<Vec<E::G2Affine>>();
            a_points.push(a_point_vec);

            let b_point_vec = (0..n + 1)
                .into_par_iter()
                .map(|j| self.y_points[j].mul(uss[i][j]).into_affine())
                .collect::<Vec<E::G2Affine>>();
            b_points.push(b_point_vec);
        }
        let c_points = (0..n)
            .into_par_iter()
            .map(|i| self.z_point.mul(rs[i]).into_affine())
            .collect::<Vec<E::G2Affine>>();
        let d_scalars = (0..n)
            .into_par_iter()
            .map(|i| self.mue.pow(rs[i].into_repr()))
            .collect::<Vec<E::Fqk>>();
        let mut d_bytes = Vec::with_capacity(n);
        for scalar in d_scalars.into_iter() {
            d_bytes.push(hash_field2bytes::<E>(scalar)?);
        }
        Ok(Ciphertext {
            a_points,
            b_points,
            c_points,
            d_bytes,
        })
    }
}

impl<E: Engine> Trapdoor<E> {
    pub fn test(&self, ct: &Ciphertext<E>) -> Result<bool, PECDKError<E>> {
        let n = ct.c_points.len();
        let m = self.t1s.len() - 1;
        let test1s = (0..n)
            .into_par_iter()
            .map(|i| {
                let c_powed = ct.c_points[i].mul(self.t3);
                let mut val = E::Fqk::one();
                for j in 0..(m + 1) {
                    let mut point2 = ct.a_points[i][j].into_projective();
                    point2.add_assign(&c_powed);
                    let paired = E::miller_loop(
                        [(&(self.t1s[j].prepare()), &(point2.into_affine().prepare()))].iter(),
                    );
                    val.mul_assign(&paired);
                }
                val
            })
            .collect::<Vec<E::Fqk>>();

        let test2_invs = (0..n)
            .into_par_iter()
            .map(|i| {
                let mut val = E::Fqk::one();
                for j in 0..(m + 1) {
                    let paired = E::miller_loop(
                        [(&(self.t2s[j].prepare()), &(ct.b_points[i][j].prepare()))].iter(),
                    );
                    val.mul_assign(&paired);
                }
                val.inverse().ok_or(PECDKError::<E>::InverseFqkError(val))
            })
            .collect::<Result<Vec<E::Fqk>, PECDKError<E>>>()?;
        let test_scalars = test1s
            .into_par_iter()
            .zip(test2_invs)
            .map(|(test1, test2_inv)| {
                let mut val = test1;
                val.mul_assign(&test2_inv);
                E::final_exponentiation(&val).unwrap()
            })
            .collect::<Vec<E::Fqk>>();
        match self.sym {
            SearchSym::AND => {
                let mut sum_valid = 0;
                for i in 0..n {
                    let left = &hash_field2bytes::<E>(test_scalars[i])?;
                    let right = &ct.d_bytes[i];
                    if left == right {
                        sum_valid += 1;
                    }
                }
                Ok(sum_valid == m)
            }
            SearchSym::OR => {
                for i in 0..n {
                    let left = &hash_field2bytes::<E>(test_scalars[i])?;
                    let right = &ct.d_bytes[i];
                    if left == right {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use paired::bls12_381::{Bls12, Fr};
    use rand::{thread_rng, Rng};
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_pecdk_valid_case_and() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let n = 70;
        let mut thread_rng = thread_rng();
        let mut keywords = Vec::with_capacity(n);
        for _ in 0..n {
            let keyword = (0..16).map(|_| thread_rng.gen()).collect::<Vec<u8>>();
            keywords.push(keyword);
        }
        let m = 70;
        assert_eq!(
            test_generic(
                keywords.clone(),
                keywords[0..m].to_vec(),
                SearchSym::AND,
                &mut rng
            ),
            true
        );
    }

    #[test]
    fn test_pecdk_valid_case_or() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let n = 70;
        let mut thread_rng = thread_rng();
        let mut keywords = Vec::with_capacity(n);
        for _ in 0..n {
            let keyword = (0..16).map(|_| thread_rng.gen()).collect::<Vec<u8>>();
            keywords.push(keyword);
        }
        let m = 70;
        assert_eq!(
            test_generic(
                keywords.clone(),
                keywords[0..m].to_vec(),
                SearchSym::OR,
                &mut rng
            ),
            true
        );
    }

    #[test]
    fn test_pecdk_invalid_case_and() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let n = 70;
        let mut thread_rng = thread_rng();
        let mut keywords = Vec::with_capacity(n);
        for _ in 0..n {
            let keyword = (0..16).map(|_| thread_rng.gen()).collect::<Vec<u8>>();
            keywords.push(keyword);
        }
        let m = 69;
        let mut invalid_keywords = keywords[0..m].to_vec();
        invalid_keywords.push(vec![0, 1, 2]);
        assert_eq!(
            test_generic(keywords, invalid_keywords, SearchSym::AND, &mut rng),
            false
        );
    }

    #[test]
    fn test_pecdk_invalid_case_or() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let n = 70;
        let mut thread_rng = thread_rng();
        let mut keywords = Vec::with_capacity(n);
        for _ in 0..n {
            let keyword = (0..16).map(|_| thread_rng.gen()).collect::<Vec<u8>>();
            keywords.push(keyword);
        }
        let m = 70;
        let mut invalid_keywords = Vec::with_capacity(m);
        for _ in 0..m {
            let keyword = (0..16).map(|_| thread_rng.gen()).collect::<Vec<u8>>();
            invalid_keywords.push(keyword);
        }
        assert_eq!(
            test_generic(keywords, invalid_keywords, SearchSym::OR, &mut rng),
            false
        );
    }

    #[test]
    fn test_pecdk_large_case_and() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let n = 256;
        let mut thread_rng = thread_rng();
        let mut keywords = Vec::with_capacity(n);
        for _ in 0..n {
            let keyword = (0..16).map(|_| thread_rng.gen()).collect::<Vec<u8>>();
            keywords.push(keyword);
        }
        let m = 256;
        assert_eq!(
            test_generic(
                keywords.clone(),
                keywords[0..m].to_vec(),
                SearchSym::AND,
                &mut rng
            ),
            true
        );
    }

    #[test]
    fn test_pecdk_large_case_or() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let n = 256;
        let mut thread_rng = thread_rng();
        let mut keywords = Vec::with_capacity(n);
        for _ in 0..n {
            let keyword = (0..16).map(|_| thread_rng.gen()).collect::<Vec<u8>>();
            keywords.push(keyword);
        }
        let m = 256;
        assert_eq!(
            test_generic(
                keywords.clone(),
                keywords[0..m].to_vec(),
                SearchSym::OR,
                &mut rng
            ),
            true
        );
    }

    fn test_generic<R: RngCore>(
        ct_keywords: Vec<Vec<u8>>,
        td_keywords: Vec<Vec<u8>>,
        sym: SearchSym,
        mut rng: R,
    ) -> bool {
        let n = ct_keywords.len();
        let secret_key = SecretKey::<Bls12>::gen(&mut rng, n);
        let public_key = secret_key.into_public_key(&mut rng);
        let ct = public_key.encrypt::<_, Fr>(ct_keywords, &mut rng).unwrap();
        let trapdoor = secret_key
            .gen_trapdoor::<_, Fr>(td_keywords, sym, &mut rng)
            .unwrap();
        trapdoor.test(&ct).unwrap()
    }
}
