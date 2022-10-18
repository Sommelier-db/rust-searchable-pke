mod prefix;
mod range;
mod utils;
pub use prefix::*;
pub use range::*;

use crate::pecdk::PECDKError;
use fff::{Field, PrimeField};
use groupy::{CurveAffine, CurveProjective};
use paired::{Engine, PairingCurveAffine};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExpError<E: Engine> {
    #[error("The number of given keywords is {0}, but the max number is {1}")]
    ExcessiveNumberOfKeywords(usize, usize),
    #[error(transparent)]
    PECDKError(#[from] PECDKError<E>),
}
