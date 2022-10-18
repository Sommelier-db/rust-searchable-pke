mod like;
mod range;
pub use like::*;
pub use range::*;

use crate::pecdk::PECDKError;
use fff::{Field, PrimeField};
use groupy::{CurveAffine, CurveProjective};
use paired::{Engine, PairingCurveAffine};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExpError<E: Engine> {
    #[error(transparent)]
    PECDKError(#[from] PECDKError<E>),
}
