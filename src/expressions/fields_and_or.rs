use std::collections::HashMap;

use super::utils::*;
use super::ExpError;
use crate::pecdk::*;
use crate::BaseROFr;
use paired::Engine;
use rand_core::RngCore;

pub fn gen_ciphertext_for_field_and_search<E: Engine, F: BaseROFr<E>, R: RngCore>(
    public_key: &PublicKey<E>,
    region_name: &str,
    field_val_map: HashMap<Vec<u8>, Vec<u8>>,
    rng: &mut R,
) -> Result<Ciphertext<E>, ExpError<E>> {
    gen_ciphertext_for_field_search::<E, F, R>(public_key, region_name, field_val_map, rng)
}

pub fn gen_ciphertext_for_field_or_search<E: Engine, F: BaseROFr<E>, R: RngCore>(
    public_key: &PublicKey<E>,
    region_name: &str,
    field_val_map: HashMap<Vec<u8>, Vec<u8>>,
    rng: &mut R,
) -> Result<Ciphertext<E>, ExpError<E>> {
    gen_ciphertext_for_field_search::<E, F, R>(public_key, region_name, field_val_map, rng)
}

pub fn gen_trapdoor_for_field_and_search<E: Engine, F: BaseROFr<E>, R: RngCore>(
    secret_key: &SecretKey<E>,
    region_name: &str,
    field_val_map: HashMap<Vec<u8>, Vec<u8>>,
    rng: &mut R,
) -> Result<Trapdoor<E>, ExpError<E>> {
    gen_trapdoor_for_field_search::<E, F, R>(
        secret_key,
        region_name,
        field_val_map,
        SearchSym::AND,
        rng,
    )
}

pub fn gen_trapdoor_for_field_or_search<E: Engine, F: BaseROFr<E>, R: RngCore>(
    secret_key: &SecretKey<E>,
    region_name: &str,
    field_val_map: HashMap<Vec<u8>, Vec<u8>>,
    rng: &mut R,
) -> Result<Trapdoor<E>, ExpError<E>> {
    gen_trapdoor_for_field_search::<E, F, R>(
        secret_key,
        region_name,
        field_val_map,
        SearchSym::OR,
        rng,
    )
}

fn gen_ciphertext_for_field_search<E: Engine, F: BaseROFr<E>, R: RngCore>(
    public_key: &PublicKey<E>,
    region_name: &str,
    field_val_map: HashMap<Vec<u8>, Vec<u8>>,
    rng: &mut R,
) -> Result<Ciphertext<E>, ExpError<E>> {
    let n_bytes = field_val_map.len();
    let max_bytes = public_key.num_keyword();
    if n_bytes > max_bytes {
        return Err(ExpError::ExcessiveNumberOfKeywords(n_bytes, max_bytes));
    }
    let n_remaining = max_bytes - n_bytes;

    let mut keywords = field_val_map
        .into_iter()
        .map(|(field, val)| {
            concat_multi_bytes(vec![
                region_name.as_bytes(),
                &vec![1u8],
                &field[..],
                &val[..],
            ])
        })
        .collect::<Vec<Vec<u8>>>();
    for _ in 0..n_remaining {
        keywords.push(concat_multi_bytes(vec![region_name.as_bytes(), &vec![0u8]]));
    }
    let ct = public_key.encrypt::<R, F>(keywords, rng)?;
    Ok(ct)
}

fn gen_trapdoor_for_field_search<E: Engine, F: BaseROFr<E>, R: RngCore>(
    secret_key: &SecretKey<E>,
    region_name: &str,
    field_val_map: HashMap<Vec<u8>, Vec<u8>>,
    sym: SearchSym,
    rng: &mut R,
) -> Result<Trapdoor<E>, ExpError<E>> {
    let n_bytes = field_val_map.len();
    let max_bytes = secret_key.num_keyword();
    if n_bytes > max_bytes {
        return Err(ExpError::ExcessiveNumberOfKeywords(n_bytes, max_bytes));
    }

    let keywords = field_val_map
        .into_iter()
        .map(|(field, val)| {
            concat_multi_bytes(vec![
                region_name.as_bytes(),
                &vec![1u8],
                &field[..],
                &val[..],
            ])
        })
        .collect::<Vec<Vec<u8>>>();
    let td = secret_key.gen_trapdoor::<R, F>(keywords, sym, rng)?;
    Ok(td)
}

#[cfg(test)]
mod test {
    use super::*;

    use paired::bls12_381::{Bls12, Fr};
    use rand::{thread_rng, Rng};
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_valid_and_case_simple() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let n = 5;
        let secret_key = SecretKey::<Bls12>::gen(&mut rng, n);
        let public_key = secret_key.into_public_key(&mut rng);
        let region_name = "test_valid_and_case_simple";
        let mut field_val_map = HashMap::new();
        let mut thread_rng = thread_rng();
        for _ in 0..n {
            let field = (0..16).map(|_| thread_rng.gen()).collect::<Vec<u8>>();
            let val = (0..16).map(|_| thread_rng.gen()).collect::<Vec<u8>>();
            field_val_map.insert(field, val);
        }
        let ct = gen_ciphertext_for_field_and_search::<_, Fr, _>(
            &public_key,
            region_name,
            field_val_map.clone(),
            &mut rng,
        )
        .unwrap();
        let trapdoor = gen_trapdoor_for_field_and_search::<_, Fr, _>(
            &secret_key,
            region_name,
            field_val_map,
            &mut rng,
        )
        .unwrap();
        assert_eq!(trapdoor.test(&ct).unwrap(), true);
    }

    #[test]
    fn test_valid_or_case_simple() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let n = 5;
        let secret_key = SecretKey::<Bls12>::gen(&mut rng, n);
        let public_key = secret_key.into_public_key(&mut rng);
        let region_name = "test_valid_or_case_simple";
        let mut field_val_map = HashMap::new();
        let mut thread_rng = thread_rng();
        for _ in 0..n {
            let field = (0..16).map(|_| thread_rng.gen()).collect::<Vec<u8>>();
            let val = (0..16).map(|_| thread_rng.gen()).collect::<Vec<u8>>();
            field_val_map.insert(field, val);
        }
        let ct = gen_ciphertext_for_field_and_search::<_, Fr, _>(
            &public_key,
            region_name,
            field_val_map.clone(),
            &mut rng,
        )
        .unwrap();
        let mut search_field_val_map = HashMap::new();
        let random_idx = thread_rng.gen::<usize>() % n;
        for (i, (field, val)) in field_val_map.iter().enumerate() {
            if i == random_idx {
                search_field_val_map.insert(field.clone(), val.clone());
            }
        }
        let trapdoor = gen_trapdoor_for_field_or_search::<_, Fr, _>(
            &secret_key,
            region_name,
            search_field_val_map,
            &mut rng,
        )
        .unwrap();
        assert_eq!(trapdoor.test(&ct).unwrap(), true);
    }
}
