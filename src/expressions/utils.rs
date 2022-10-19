pub(crate) fn concat_multi_bytes(bytes_vec: Vec<&[u8]>) -> Vec<u8> {
    let mut all_bytes = Vec::new();
    for bytes in bytes_vec {
        all_bytes.extend_from_slice(bytes);
    }
    all_bytes
}
