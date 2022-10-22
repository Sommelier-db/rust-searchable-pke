#[cfg(feature = "c_api")]
mod c_api;

mod fields_and_or;
mod prefix;
mod range;
mod utils;

#[cfg(feature = "c_api")]
pub use c_api::*;

pub use fields_and_or::*;
pub use prefix::*;
pub use range::*;

use crate::pecdk::PECDKError;
use paired::Engine;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExpError<E: Engine> {
    #[error("The number of given keywords is {0}, but the max number is {1}")]
    ExcessiveNumberOfKeywords(usize, usize),
    #[error(transparent)]
    PECDKError(#[from] PECDKError<E>),
}
