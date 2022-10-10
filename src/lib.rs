mod hashes;
pub mod pecdk;
pub mod peks;
mod utils;
use fff::{PrimeField, ScalarEngine, SqrtField};
pub use hashes::*;
use paired::{
    bls12_381::{Bls12, Fr},
    BaseFromRO, Engine,
};

pub trait BaseROFr<E: Engine>: BaseFromRO + Clone + From<E::Fr> + Into<E::Fr> {}

impl BaseROFr<Bls12> for Fr {}
