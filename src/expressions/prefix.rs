use super::utils::*;
use super::ExpError;
use crate::pecdk::*;
use crate::BaseROFr;
use paired::Engine;
use rand_core::RngCore;

pub fn gen_ciphertext_for_prefix_search<E: Engine, F: BaseROFr<E>, R: RngCore>(
    public_key: &PublicKey<E>,
    region_name: &str,
    string: &str,
    rng: &mut R,
) -> Result<Ciphertext<E>, ExpError<E>> {
    let bytes = string.as_bytes();
    let n_bytes = bytes.len();
    let max_bytes = public_key.num_keyword();
    if n_bytes > max_bytes {
        return Err(ExpError::ExcessiveNumberOfKeywords(n_bytes, max_bytes));
    }
    let n_remaining = max_bytes - n_bytes;

    let mut keywords = bytes
        .into_iter()
        .enumerate()
        .map(|(idx, byte)| {
            concat_multi_bytes(vec![
                region_name.as_bytes(),
                &idx.to_be_bytes(),
                &vec![1u8, *byte],
            ])
        })
        .collect::<Vec<Vec<u8>>>();
    for idx in 0..n_remaining {
        keywords.push(concat_multi_bytes(vec![
            region_name.as_bytes(),
            &idx.to_be_bytes(),
            &vec![0u8, 0u8],
        ]));
    }
    let ct = public_key.encrypt::<R, F>(keywords, rng)?;
    Ok(ct)
}

pub fn gen_trapdoor_for_prefix_search<E: Engine, F: BaseROFr<E>, R: RngCore>(
    secret_key: &SecretKey<E>,
    region_name: &str,
    prefix: &str,
    rng: &mut R,
) -> Result<Trapdoor<E>, ExpError<E>> {
    let bytes = prefix.as_bytes();
    let n_bytes = bytes.len();
    let max_bytes = secret_key.num_keyword();
    if n_bytes > max_bytes {
        return Err(ExpError::ExcessiveNumberOfKeywords(n_bytes, max_bytes));
    }

    let keywords = bytes
        .into_iter()
        .enumerate()
        .map(|(idx, byte)| {
            concat_multi_bytes(vec![
                region_name.as_bytes(),
                &idx.to_be_bytes(),
                &vec![1u8, *byte],
            ])
        })
        .collect::<Vec<Vec<u8>>>();
    let td = secret_key.gen_trapdoor::<R, F>(keywords, SearchSym::AND, rng)?;
    Ok(td)
}

pub fn gen_trapdoor_for_prefix_search_exact<E: Engine, F: BaseROFr<E>, R: RngCore>(
    secret_key: &SecretKey<E>,
    region_name: &str,
    string: &str,
    rng: &mut R,
) -> Result<Trapdoor<E>, ExpError<E>> {
    let bytes = string.as_bytes();
    let n_bytes = bytes.len();
    let max_bytes = secret_key.num_keyword();
    if n_bytes > max_bytes {
        return Err(ExpError::ExcessiveNumberOfKeywords(n_bytes, max_bytes));
    }
    let n_remaining = max_bytes - n_bytes;

    let mut keywords = bytes
        .into_iter()
        .enumerate()
        .map(|(idx, byte)| {
            concat_multi_bytes(vec![
                region_name.as_bytes(),
                &idx.to_be_bytes(),
                &vec![1u8, *byte],
            ])
        })
        .collect::<Vec<Vec<u8>>>();
    for idx in 0..n_remaining {
        keywords.push(concat_multi_bytes(vec![
            region_name.as_bytes(),
            &idx.to_be_bytes(),
            &vec![0u8, 0u8],
        ]));
    }
    let td = secret_key.gen_trapdoor::<R, F>(keywords, SearchSym::AND, rng)?;
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
    fn test_valid_prefix_case_simple() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let n = 5;
        let secret_key = SecretKey::<Bls12>::gen(&mut rng, n);
        let public_key = secret_key.into_public_key(&mut rng);
        let region_name = "test_valid_prefix_case_simple";
        let string = "abcde";
        let ct = gen_ciphertext_for_prefix_search::<_, Fr, _>(
            &public_key,
            region_name,
            string,
            &mut rng,
        )
        .unwrap();
        let prefix = "abc";
        let trapdoor =
            gen_trapdoor_for_prefix_search::<_, Fr, _>(&secret_key, region_name, prefix, &mut rng)
                .unwrap();
        assert_eq!(trapdoor.test(&ct).unwrap(), true);
    }

    #[test]
    fn test_valid_prefix_case_non_ascii() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let string = "アメンボ赤いなあいうえお";
        let n = string.len();
        let secret_key = SecretKey::<Bls12>::gen(&mut rng, n);
        let public_key = secret_key.into_public_key(&mut rng);
        let region_name = "test_valid_prefix_case_non_ascii";
        let ct = gen_ciphertext_for_prefix_search::<_, Fr, _>(
            &public_key,
            region_name,
            string,
            &mut rng,
        )
        .unwrap();
        let prefix = "アメンボ";
        let trapdoor =
            gen_trapdoor_for_prefix_search::<_, Fr, _>(&secret_key, region_name, prefix, &mut rng)
                .unwrap();
        assert_eq!(trapdoor.test(&ct).unwrap(), true);
    }

    #[test]
    fn test_invalid_prefix_case_simple() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let n = 5;
        let secret_key = SecretKey::<Bls12>::gen(&mut rng, n);
        let public_key = secret_key.into_public_key(&mut rng);
        let region_name = "test_invalid_prefix_case_simple";
        let string = "abcde";
        let ct = gen_ciphertext_for_prefix_search::<_, Fr, _>(
            &public_key,
            region_name,
            string,
            &mut rng,
        )
        .unwrap();
        let prefix = "de";
        let trapdoor =
            gen_trapdoor_for_prefix_search::<_, Fr, _>(&secret_key, region_name, prefix, &mut rng)
                .unwrap();
        assert_eq!(trapdoor.test(&ct).unwrap(), false);
    }

    #[test]
    fn test_invalid_prefix_case_non_ascii() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let string = "アメンボ赤いなあいうえお";
        let n = string.len();
        let secret_key = SecretKey::<Bls12>::gen(&mut rng, n);
        let public_key = secret_key.into_public_key(&mut rng);
        let region_name = "test_invalid_prefix_case_non_ascii";
        let ct = gen_ciphertext_for_prefix_search::<_, Fr, _>(
            &public_key,
            region_name,
            string,
            &mut rng,
        )
        .unwrap();
        let prefix = "アメンボ赤いの";
        let trapdoor =
            gen_trapdoor_for_prefix_search::<_, Fr, _>(&secret_key, region_name, prefix, &mut rng)
                .unwrap();
        assert_eq!(trapdoor.test(&ct).unwrap(), false);
    }

    #[test]
    fn test_valid_prefix_case_exact() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let n = 5;
        let secret_key = SecretKey::<Bls12>::gen(&mut rng, n);
        let public_key = secret_key.into_public_key(&mut rng);
        let region_name = "test_valid_prefix_case_simple";
        let string = "abcde";
        let ct = gen_ciphertext_for_prefix_search::<_, Fr, _>(
            &public_key,
            region_name,
            string,
            &mut rng,
        )
        .unwrap();
        let prefix = "abcde";
        let trapdoor = gen_trapdoor_for_prefix_search_exact::<_, Fr, _>(
            &secret_key,
            region_name,
            prefix,
            &mut rng,
        )
        .unwrap();
        assert_eq!(trapdoor.test(&ct).unwrap(), true);
    }

    #[test]
    fn test_invalid_prefix_case_exact() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let n = 5;
        let secret_key = SecretKey::<Bls12>::gen(&mut rng, n);
        let public_key = secret_key.into_public_key(&mut rng);
        let region_name = "test_valid_prefix_case_simple";
        let string = "abcde";
        let ct = gen_ciphertext_for_prefix_search::<_, Fr, _>(
            &public_key,
            region_name,
            string,
            &mut rng,
        )
        .unwrap();
        let prefix = "abcd";
        let trapdoor = gen_trapdoor_for_prefix_search_exact::<_, Fr, _>(
            &secret_key,
            region_name,
            prefix,
            &mut rng,
        )
        .unwrap();
        assert_eq!(trapdoor.test(&ct).unwrap(), false);
    }
}
