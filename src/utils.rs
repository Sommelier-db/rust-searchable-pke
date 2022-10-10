use ec_gpu_gen::fft_cpu::serial_fft;
use fff::{Field, PrimeField};
use itertools::Itertools;
use paired::Engine;

pub(crate) fn polynomial_from_roots<F: PrimeField>(roots: &[F]) -> Vec<F> {
    let m = roots.len();
    let log_m = (m as f64).log2() as u32;
    assert!(log_m <= F::S);
    let zero = F::zero();
    let one = F::one();
    let mut minus_one = zero.clone();
    minus_one.sub_assign(&one);

    let mut coefficients: Vec<F> = Vec::with_capacity(m);
    let mut minus_one_powed = one;
    for k in 0..m {
        let mut sum = zero.clone();
        for comb in (0..m).combinations(k + 1) {
            let mut term = one.clone();
            for i in comb.into_iter() {
                term.mul_assign(&roots[i]);
            }
            sum.add_assign(&term);
        }
        minus_one_powed.mul_assign(&minus_one);
        sum.mul_assign(&minus_one_powed);
        coefficients.push(sum);
    }
    coefficients.reverse();
    coefficients.push(one);

    assert_eq!(coefficients.len(), m + 1);
    coefficients
}

#[cfg(test)]
mod test {
    use super::*;
    use paired::bls12_381::Fr;
    use rand::{thread_rng, Rng};
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn degree_one() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let one = Fr::random(&mut rng);
        let roots = vec![one];
        let coeffs = polynomial_from_roots(&roots);
        for root in roots.iter() {
            let mut sum = Fr::zero();
            let mut base = one.clone();
            for i in 0..2 {
                let mut coefficient = coeffs[i].clone();
                coefficient.mul_assign(&base);
                sum.add_assign(&coefficient);
                base.mul_assign(root);
            }
            assert_eq!(sum, Fr::zero());
        }
    }

    #[test]
    fn degree_two() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let one = Fr::random(&mut rng);
        let two = Fr::random(&mut rng);
        let roots = vec![one, two];
        let n = roots.len();
        let coeffs = polynomial_from_roots(&roots);
        for root in roots.iter() {
            let mut sum = Fr::zero();
            let mut base = Fr::one();
            for i in 0..(n + 1) {
                let mut coefficient = coeffs[i].clone();
                coefficient.mul_assign(&base);
                sum.add_assign(&coefficient);
                base.mul_assign(root);
            }
            assert_eq!(sum, Fr::zero());
        }
    }

    #[test]
    fn degree_16() {
        let mut rng = <XorShiftRng as SeedableRng>::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let n = 16;
        let roots = (0..n).map(|_| Fr::random(&mut rng)).collect::<Vec<Fr>>();
        let coeffs = polynomial_from_roots(&roots);
        for root in roots.iter() {
            let mut sum = Fr::zero();
            let mut base = Fr::one();
            for i in 0..(n + 1) {
                let mut coefficient = coeffs[i].clone();
                coefficient.mul_assign(&base);
                sum.add_assign(&coefficient);
                base.mul_assign(root);
            }
            assert_eq!(sum, Fr::zero());
        }
    }
}
