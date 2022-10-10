use crate::BaseROFr;
use digest::{Digest, ExtendableOutput, Update};
use fff::{Field, PrimeField, PrimeFieldDecodingError, PrimeFieldRepr};
use groupy::CurveProjective;
use paired::{hash_to_field, BaseFromRO, Compress, Engine, ExpandMsgXmd, FromRO, HashToCurve};
use sha2::Sha256;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ECHashError {
    #[error(transparent)]
    PrimeDecode(#[from] PrimeFieldDecodingError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

//https://github.com/filecoin-project/paired/blob/master/src/hash_to_field.rs
pub(crate) fn hash_bytes2field<F: BaseROFr<E>, E: Engine>(
    bytes: &[u8],
    tag: &[u8],
) -> Result<E::Fr, ECHashError> {
    let fields = hash_to_field::<F, ExpandMsgXmd<Sha256>>(bytes, tag, 1);
    Ok(fields[0].clone().into())
}

pub(crate) fn hash_bytes2point<E: Engine>(bytes: &[u8]) -> E::G1 {
    <E::G1 as CurveProjective>::hash(bytes)
}

pub(crate) fn hash_field2bytes<E: Engine>(field: E::Fqk) -> Result<Vec<u8>, ECHashError> {
    let mut field_bytes = Vec::new();
    field.write_compressed(&mut field_bytes)?;
    Ok(<Sha256 as Digest>::digest(&field_bytes).to_vec())
}
