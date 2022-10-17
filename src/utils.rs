use fff::PrimeField;
use rayon::prelude::*;

/// References
/// 1. [vitalik's python implementation of ZK-STARK](https://github.com/ethereum/research/blob/master/mimc_stark/poly_utils.py)
/// 2. [hrmk1o3's Rust implementation of ZK-STARK](https://github.com/InternetMaximalism/stark-pure-rust/blob/develop/packages/fri/src/poly_utils.rs)

pub(crate) fn polynomial_from_roots<F: PrimeField>(roots: &[F]) -> Vec<F> {
    let m = roots.len() + 1;

    let xs = (0..m).fold(Vec::with_capacity(m), |mut vec, i| {
        if i == 0 {
            vec.push(F::zero());
        } else {
            let mut v = vec[i - 1].clone();
            v.add_assign(&F::one());
            vec.push(v);
        }
        vec
    });
    let root_poly = zpoly(&xs);
    let numerator_polys = xs
        .par_iter()
        .map(|x| {
            let mut minus_x = F::zero();
            minus_x.sub_assign(x);
            div_polys(&root_poly, &[minus_x, F::one()])
        })
        .collect::<Vec<Vec<F>>>();
    let denominators = (0..m)
        .into_par_iter()
        .map(|i| eval_poly_at(&numerator_polys[i], xs[i]))
        .collect::<Vec<F>>();
    let inv_denoms = multi_inv(&denominators);

    let ys = (0..m)
        .into_par_iter()
        .map(|i| {
            let mut y = F::one();
            for j in 0..(m - 1) {
                let mut factor = xs[i].clone();
                factor.sub_assign(&roots[j]);
                y.mul_assign(&factor);
            }
            y
        })
        .collect::<Vec<F>>();

    let mut coefficients = vec![F::zero(); m];
    for i in 0..m {
        let mut yslice = ys[i];
        yslice.mul_assign(&inv_denoms[i]);
        for j in 0..m {
            let mut term = numerator_polys[i][j].clone();
            term.mul_assign(&yslice);
            coefficients[j].add_assign(&term);
        }
    }
    coefficients
}

fn eval_poly_at<F: PrimeField>(coeffs: &[F], x: F) -> F {
    let mut result = F::zero();
    let mut base = F::one();
    for coeff in coeffs.iter() {
        let mut term = coeff.clone();
        term.mul_assign(&base);
        result.add_assign(&term);
        base.mul_assign(&x);
    }
    result
}

// Original: https://github.com/InternetMaximalism/stark-pure-rust/blob/develop/packages/fri/src/poly_utils.rs#L362
fn zpoly<F: PrimeField>(xs: &[F]) -> Vec<F> {
    let mut root = vec![F::one()];
    for i in 0..xs.len() {
        root.push(F::zero());
        for j in (0..(i + 1)).rev() {
            let mut term = root[j];
            term.mul_assign(&xs[i]);
            root[j + 1].sub_assign(&term);
        }
    }
    root.reverse();
    root
}

fn div_polys<F: PrimeField>(a: &[F], b: &[F]) -> Vec<F> {
    assert!(a.len() >= b.len());
    let mut a = a.into_iter().map(|v| v.clone()).collect::<Vec<F>>();
    let mut outputs = Vec::new();
    let mut apos = a.len() - 1;
    let bpos = b.len() - 1;
    let diff = apos - bpos;
    for d in (0..(diff + 1)).rev() {
        let mut quot = a[apos].clone();
        quot.mul_assign(&b[bpos].inverse().unwrap());
        outputs.push(quot);
        for i in (0..bpos + 1).rev() {
            let mut term = b[i].clone();
            term.mul_assign(&quot);
            a[d + i].sub_assign(&term);
        }
        apos -= 1;
    }
    outputs.reverse();
    outputs
}

fn multi_inv<F: PrimeField>(values: &[F]) -> Vec<F> {
    let mut partials = vec![F::one()];
    for i in 0..values.len() {
        let mut v = partials[partials.len() - 1].clone();
        if values[i] != F::zero() {
            v.mul_assign(&values[i]);
        } else {
            v.mul_assign(&F::one());
        }
        partials.push(v)
    }
    let mut inv = partials[partials.len() - 1].inverse().unwrap();
    let mut outputs = vec![F::zero(); values.len()];
    for i in (0..values.len()).rev() {
        let mut v = partials[i].clone();
        outputs[i] = if values[i] != F::zero() {
            v.mul_assign(&inv);
            v
        } else {
            v.mul_assign(&F::zero());
            v
        };
        if values[i] != F::zero() {
            inv.mul_assign(&values[i]);
        } else {
            inv.mul_assign(&F::one());
        };
    }
    outputs
}

#[cfg(test)]
mod test {
    use super::*;
    use fff::Field;
    use paired::bls12_381::Fr;
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
            let mut base = Fr::one();
            for coeff in coeffs.iter() {
                let mut v = coeff.clone();
                v.mul_assign(&base);
                sum.add_assign(&v);
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
        let coeffs = polynomial_from_roots(&roots);
        for root in roots.iter() {
            let mut sum = Fr::zero();
            let mut base = Fr::one();
            for coeff in coeffs.iter() {
                let mut v = coeff.clone();
                v.mul_assign(&base);
                sum.add_assign(&v);
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
            for coeff in coeffs.iter() {
                let mut v = coeff.clone();
                v.mul_assign(&base);
                sum.add_assign(&v);
                base.mul_assign(root);
            }
            assert_eq!(sum, Fr::zero());
        }
    }
}
