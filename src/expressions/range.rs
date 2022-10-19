use std::collections::HashSet;

use super::utils::*;
use super::ExpError;
use crate::pecdk::*;
use crate::BaseROFr;
use multiset::HashMultiSet;
use paired::Engine;
use rand_core::RngCore;

pub fn compute_max_keyword_size(bit_size: usize) -> usize {
    2 * bit_size
}

pub fn gen_ciphertext_for_range_search<E: Engine, F: BaseROFr<E>, R: RngCore>(
    public_key: &PublicKey<E>,
    region_name: &str,
    bit_size: usize,
    val: u64,
    rng: &mut R,
) -> Result<Ciphertext<E>, ExpError<E>> {
    let max_keyword_size = compute_max_keyword_size(bit_size);
    let bits = uint2bits(val, bit_size);
    let sliced_uints = (0..bit_size)
        .map(|i| {
            let sliced_bits = &bits[0..(i + 1)];
            (i, bits2uint(sliced_bits))
        })
        .collect::<Vec<(usize, u64)>>();
    let mut keywords: Vec<Vec<u8>> = sliced_uints
        .into_iter()
        .map(|(i, val)| {
            concat_multi_bytes(vec![
                region_name.as_bytes(),
                &vec![1u8],
                &(i + 1).to_be_bytes(),
                &val.to_be_bytes(),
            ])
        })
        .collect();
    for _ in 0..(max_keyword_size - keywords.len()) {
        keywords.push(concat_multi_bytes(vec![
            region_name.as_bytes(),
            &vec![0u8],
            &0u64.to_be_bytes(),
            &0u64.to_be_bytes(),
        ]));
    }
    let ct = public_key.encrypt::<R, F>(keywords, rng)?;
    Ok(ct)
}

pub fn gen_trapdoor_for_range_search<E: Engine, F: BaseROFr<E>, R: RngCore>(
    secret_key: &SecretKey<E>,
    region_name: &str,
    min: u64,
    max: u64,
    bit_size: usize,
    rng: &mut R,
) -> Result<Trapdoor<E>, ExpError<E>> {
    let max_keyword_size = compute_max_keyword_size(bit_size);
    let nodes = get_canonical_cover_nodes(min, max, bit_size);
    let mut keywords = nodes
        .into_iter()
        .map(|node| {
            concat_multi_bytes(vec![
                region_name.as_bytes(),
                &vec![1u8],
                &node.len().to_be_bytes(),
                &bits2uint(&node).to_be_bytes(),
            ])
        })
        .collect::<Vec<Vec<u8>>>();
    for _ in 0..(max_keyword_size - keywords.len()) {
        keywords.push(concat_multi_bytes(vec![
            region_name.as_bytes(),
            &vec![0u8],
            &1u64.to_be_bytes(),
            &1u64.to_be_bytes(),
        ]));
    }
    let td = secret_key.gen_trapdoor::<R, F>(keywords, SearchSym::OR, rng)?;
    Ok(td)
}

fn get_canonical_cover_nodes(min: u64, max: u64, bit_size: usize) -> HashSet<Vec<bool>> {
    let n1 = max - min + 1;
    let l = (n1 as f64 + 1.0).log2().floor() as usize;
    let n2 = n1 - (1 << l) + 1;

    let mut nodes = HashSet::new();
    let mut allowed_lens = HashMultiSet::new();
    for i in 0..l {
        allowed_lens.insert(bit_size - i);
    }
    let n2_bits = uint2bits(n2, bit_size);
    for (i, bit) in n2_bits.into_iter().rev().enumerate() {
        if bit {
            allowed_lens.insert(bit_size - i);
        }
    }

    let mut min = min;
    while !allowed_lens.is_empty() {
        let next_node = get_canonical_next_max(min, max, bit_size, &allowed_lens);
        min = compute_max_uint(&next_node, bit_size) + 1;
        allowed_lens.remove(&next_node.len());
        nodes.insert(next_node);
    }
    nodes
}

fn get_canonical_next_max(
    min: u64,
    max: u64,
    bit_size: usize,
    allowed_lens: &HashMultiSet<usize>,
) -> Vec<bool> {
    let mut bits_pattern = uint2bits(min, bit_size);
    let min_size_in_set = *allowed_lens.iter().min().unwrap();
    while bits_pattern.len() >= 2
        && (compute_min_uint(&bits_pattern[0..bits_pattern.len() - 1], bit_size) >= min)
        && (compute_max_uint(&bits_pattern[0..bits_pattern.len() - 1], bit_size) <= max)
        && (allowed_lens.contains(&(bits_pattern.len() - 1))
            || bits_pattern.len() - 1 >= min_size_in_set)
    {
        bits_pattern.pop();
    }
    bits_pattern
}

fn compute_min_uint(bits: &[bool], bit_size: usize) -> u64 {
    let mut min_bits = bits.to_vec();
    min_bits.append(&mut vec![false; bit_size - bits.len()]);
    bits2uint(&min_bits)
}

fn compute_max_uint(bits: &[bool], bit_size: usize) -> u64 {
    let mut max_bits = bits.to_vec();
    max_bits.append(&mut vec![true; bit_size - bits.len()]);
    bits2uint(&max_bits)
}

fn uint2bits(val: u64, size: usize) -> Vec<bool> {
    let bytes = val.to_le_bytes();
    let mut bits = Vec::with_capacity(size);
    for byte in bytes {
        for i in 0..8 {
            if bits.len() >= size {
                bits.reverse();
                return bits;
            }
            let bit = (byte >> i) & 1 == 1;
            bits.push(bit);
        }
    }
    bits.reverse();
    bits
}

fn bits2uint(bits: &[bool]) -> u64 {
    let num_last_bits = bits.len() % 8;
    let num_padding = if num_last_bits == 0 {
        0
    } else {
        8 - num_last_bits
    };
    let mut padded_bits = vec![false; num_padding];
    padded_bits.append(&mut bits.to_vec());
    let bytes = padded_bits
        .chunks_exact(8)
        .map(|bits| {
            let mut val = 0;
            for (i, bit) in bits.iter().enumerate() {
                let b = if *bit { 1 } else { 0 };
                val += b << (7 - i);
            }
            val
        })
        .collect::<Vec<u8>>();
    let num_byte_padding = 8 - bytes.len();
    let mut fit_bytes = [0u8; 8];
    for i in 0..(8 - num_byte_padding) {
        fit_bytes[i] = 0;
    }
    for i in 0..bytes.len() {
        fit_bytes[num_byte_padding + i] = bytes[i];
    }
    u64::from_be_bytes(fit_bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    use paired::bls12_381::{Bls12, Fr};
    use rand::{thread_rng, Rng};
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_valid_range_case_simple() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let bit_size = 5;
        let n = compute_max_keyword_size(bit_size);
        let secret_key = SecretKey::<Bls12>::gen(&mut rng, n);
        let public_key = secret_key.into_public_key(&mut rng);
        let region_name = "test_valid_range_case_simple";
        let min = 0;
        let max = 19;
        let val = 12;
        let ct = gen_ciphertext_for_range_search::<_, Fr, _>(
            &public_key,
            region_name,
            bit_size,
            val,
            &mut rng,
        )
        .unwrap();
        let trapdoor = gen_trapdoor_for_range_search::<_, Fr, _>(
            &secret_key,
            region_name,
            min,
            max,
            bit_size,
            &mut rng,
        )
        .unwrap();
        assert_eq!(trapdoor.test(&ct).unwrap(), true);
    }

    #[test]
    fn test_invalid_range_case_simple() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let bit_size = 5;
        let n = compute_max_keyword_size(bit_size);
        let secret_key = SecretKey::<Bls12>::gen(&mut rng, n);
        let public_key = secret_key.into_public_key(&mut rng);
        let region_name = "test_invalid_range_case_simple";
        let min = 2;
        let max = 20;
        let val = 1;
        let ct = gen_ciphertext_for_range_search::<_, Fr, _>(
            &public_key,
            region_name,
            bit_size,
            val,
            &mut rng,
        )
        .unwrap();
        let trapdoor = gen_trapdoor_for_range_search::<_, Fr, _>(
            &secret_key,
            region_name,
            min,
            max,
            bit_size,
            &mut rng,
        )
        .unwrap();
        assert_eq!(trapdoor.test(&ct).unwrap(), false);
    }

    #[test]
    fn get_canonical_next_max_test() {
        let nodes = get_canonical_cover_nodes(0, 19, 5);
        let mut correct_set = HashSet::<Vec<bool>>::new();
        correct_set.insert(vec![false, false]);
        correct_set.insert(vec![false, true, false]);
        correct_set.insert(vec![false, true, true]);
        correct_set.insert(vec![true, false, false, false]);
        correct_set.insert(vec![true, false, false, true, false]);
        correct_set.insert(vec![true, false, false, true, true]);
        assert_eq!(nodes, correct_set);
    }

    #[test]
    fn bits_uint_convert_test() {
        let mut rng = thread_rng();
        let test_uint = (rng.gen::<u8>() % (1 << 5)) as u64;
        let bits = uint2bits(test_uint, 5);
        let recovered = bits2uint(&bits);
        assert_eq!(test_uint, recovered);
    }
}
