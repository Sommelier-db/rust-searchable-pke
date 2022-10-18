use super::ExpError;
use crate::pecdk::PECDKError;
use fff::{Field, PrimeField};
use groupy::{CurveAffine, CurveProjective};
use paired::{Engine, PairingCurveAffine};

pub enum ParsedStringType {
    Fix { position: usize, value: String },
    Wildcard { position: usize },
}
