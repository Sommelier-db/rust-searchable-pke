use crate::PEKSError;
use groupy::CurveProjective;
use paired::{Compress, Engine, HashToCurve};
use sha2::{Digest, Sha256};

pub(crate) fn hash_bytes2point<E: Engine>(bytes: &[u8]) -> E::G1 {
    <E::G1 as CurveProjective>::hash(bytes)
}

pub(crate) fn hash_field2bytes<E: Engine>(field: E::Fqk) -> Result<Vec<u8>, PEKSError> {
    let mut field_bytes = Vec::new();
    field.write_compressed(&mut field_bytes)?;
    Ok(Sha256::digest(&field_bytes).to_vec())
}
