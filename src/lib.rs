pub mod expressions;
mod hashes;
pub mod pecdk;
pub mod peks;
mod utils;

#[cfg(feature = "c_api")]
mod c_utils;

use paired::{
    bls12_381::{Bls12, Fr},
    BaseFromRO, Engine,
};

pub trait BaseROFr<E: Engine>: BaseFromRO + Clone + From<E::Fr> + Into<E::Fr> {}

impl BaseROFr<Bls12> for Fr {}
