mod expressions;
mod hashes;
mod pecdk;
mod peks;
mod utils;

#[cfg(feature = "c_api")]
mod c_utils;

pub use crate::expressions::*;
pub use crate::hashes::*;
pub use crate::pecdk::*;
pub use crate::peks::*;
use paired::{
    bls12_381::{Bls12, Fr},
    BaseFromRO, Engine,
};

pub trait BaseROFr<E: Engine>: BaseFromRO + Clone + From<E::Fr> + Into<E::Fr> {}

impl BaseROFr<Bls12> for Fr {}
