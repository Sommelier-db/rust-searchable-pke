use super::*;
use crate::c_utils::*;
use crate::pecdk::*;
use core::slice;
use errno::{set_errno, Errno};
use paired::bls12_381::{Bls12, Fr};
use rand_core::OsRng;
use std::collections::HashMap;
use std::os::raw::c_char;
use std::os::raw::c_uint;

#[no_mangle]
pub extern "C" fn c_gen_ciphertext_for_field_search(
    public_key: CPecdkPublicKey,
    region_name: *mut c_char,
    num_fields: c_uint,
    fields: *mut *mut c_char,
    vals: *mut *mut c_char,
) -> CPecdkCiphertext {
    let mut rng = OsRng;
    let pk = match serde_json::from_str::<PublicKey<Bls12>>(&ptr2str(public_key.ptr)) {
        Ok(pk) => pk,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkCiphertext {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let region_name = ptr2str(region_name);

    let num_fields: usize = match num_fields.try_into() {
        Ok(num) => num,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkCiphertext {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let fields_slice = unsafe { slice::from_raw_parts(fields, num_fields) };
    let fields = fields_slice
        .into_iter()
        .map(|field| ptr2str(*field).as_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>();
    let vals_slice = unsafe { slice::from_raw_parts(vals, num_fields) };
    let vals = vals_slice
        .into_iter()
        .map(|val| ptr2str(*val).as_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>();
    let mut field_val_map = HashMap::<Vec<u8>, Vec<u8>>::new();
    for (field, val) in fields.into_iter().zip(vals) {
        field_val_map.insert(field, val);
    }
    let ct = gen_ciphertext_for_field_search::<_, Fr, _>(&pk, region_name, field_val_map, &mut rng)
        .expect("Fail to generate a ciphertext in c_gen_ciphertext_for_field_search");
    let ct_str = serde_json::to_string(&ct).expect(
        "Fail to convert a ciphertext to a string in c_gen_ciphertext_for_field_generic_search",
    );
    CPecdkCiphertext {
        ptr: str2ptr(ct_str),
    }
}

#[no_mangle]
pub extern "C" fn c_gen_trapdoor_for_field_and_search(
    secret_key: CPecdkSecretKey,
    region_name: *mut c_char,
    num_fields: c_uint,
    fields: *mut *mut c_char,
    vals: *mut *mut c_char,
) -> CPecdkTrapdoor {
    c_gen_trapdoor_for_field_search_generic(
        secret_key,
        region_name,
        num_fields,
        fields,
        vals,
        SearchSym::AND,
    )
}

#[no_mangle]
pub extern "C" fn c_gen_trapdoor_for_field_or_search(
    secret_key: CPecdkSecretKey,
    region_name: *mut c_char,
    num_fields: c_uint,
    fields: *mut *mut c_char,
    vals: *mut *mut c_char,
) -> CPecdkTrapdoor {
    c_gen_trapdoor_for_field_search_generic(
        secret_key,
        region_name,
        num_fields,
        fields,
        vals,
        SearchSym::OR,
    )
}

fn c_gen_trapdoor_for_field_search_generic(
    secret_key: CPecdkSecretKey,
    region_name: *mut c_char,
    num_fields: c_uint,
    fields: *mut *mut c_char,
    vals: *mut *mut c_char,
    sym: SearchSym,
) -> CPecdkTrapdoor {
    let mut rng = OsRng;
    let sk = match serde_json::from_str::<SecretKey<Bls12>>(&ptr2str(secret_key.ptr)) {
        Ok(sk) => sk,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkTrapdoor {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let region_name = ptr2str(region_name);

    let num_fields: usize = match num_fields.try_into() {
        Ok(num) => num,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkTrapdoor {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let fields_slice = unsafe { slice::from_raw_parts(fields, num_fields) };
    let fields = fields_slice
        .into_iter()
        .map(|field| ptr2str(*field).as_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>();
    let vals_slice = unsafe { slice::from_raw_parts(vals, num_fields) };
    let vals = vals_slice
        .into_iter()
        .map(|val| ptr2str(*val).as_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>();
    let mut field_val_map = HashMap::<Vec<u8>, Vec<u8>>::new();
    for (field, val) in fields.into_iter().zip(vals) {
        field_val_map.insert(field, val);
    }
    let td = match sym {
        SearchSym::AND => {
            gen_trapdoor_for_field_and_search::<_, Fr, _>(&sk, region_name, field_val_map, &mut rng)
                .expect("Fail to generate a trapdoor in c_gen_trapdoor_for_field_and_search")
        }
        SearchSym::OR => {
            gen_trapdoor_for_field_or_search::<_, Fr, _>(&sk, region_name, field_val_map, &mut rng)
                .expect("Fail to generate a trapdoor in c_gen_trapdoor_for_field_or_search")
        }
    };
    let td_str = serde_json::to_string(&td).expect(
        "Fail to convert a ciphertext to a string in c_gen_trapdoor_for_field_search_generic",
    );
    CPecdkTrapdoor {
        ptr: str2ptr(td_str),
    }
}

#[no_mangle]
pub extern "C" fn c_gen_ciphertext_for_prefix_search(
    public_key: CPecdkPublicKey,
    region_name: *mut c_char,
    string: *mut c_char,
) -> CPecdkCiphertext {
    let mut rng = OsRng;
    let pk = match serde_json::from_str::<PublicKey<Bls12>>(&ptr2str(public_key.ptr)) {
        Ok(pk) => pk,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkCiphertext {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let region_name = ptr2str(region_name);
    let string = ptr2str(string);
    let ct = gen_ciphertext_for_prefix_search::<_, Fr, _>(&pk, region_name, string, &mut rng)
        .expect("Fail to generate a ciphertext in c_gen_ciphertext_for_prefix_search");
    let ct_str = serde_json::to_string(&ct)
        .expect("Fail to convert a ciphertext to a string in c_gen_ciphertext_for_prefix_search");
    CPecdkCiphertext {
        ptr: str2ptr(ct_str),
    }
}

#[no_mangle]
pub extern "C" fn c_gen_trapdoor_for_prefix_search(
    secret_key: CPecdkSecretKey,
    region_name: *mut c_char,
    prefix: *mut c_char,
) -> CPecdkTrapdoor {
    let mut rng = OsRng;
    let sk = match serde_json::from_str::<SecretKey<Bls12>>(&ptr2str(secret_key.ptr)) {
        Ok(sk) => sk,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkTrapdoor {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let region_name = ptr2str(region_name);
    let prefix = ptr2str(prefix);

    let td = gen_trapdoor_for_prefix_search::<_, Fr, _>(&sk, region_name, prefix, &mut rng)
        .expect("Fail to generate a trapdoor in c_gen_trapdoor_for_prefix_search");
    let td_str = serde_json::to_string(&td)
        .expect("Fail to convert a ciphertext to a string in c_gen_trapdoor_for_prefix_search");
    CPecdkTrapdoor {
        ptr: str2ptr(td_str),
    }
}

#[no_mangle]
pub extern "C" fn c_gen_trapdoor_for_prefix_search_exact(
    secret_key: CPecdkSecretKey,
    region_name: *mut c_char,
    string: *mut c_char,
) -> CPecdkTrapdoor {
    let mut rng = OsRng;
    let sk = match serde_json::from_str::<SecretKey<Bls12>>(&ptr2str(secret_key.ptr)) {
        Ok(sk) => sk,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkTrapdoor {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let region_name = ptr2str(region_name);
    let string = ptr2str(string);

    let td = gen_trapdoor_for_prefix_search_exact::<_, Fr, _>(&sk, region_name, string, &mut rng)
        .expect("Fail to generate a trapdoor in c_gen_trapdoor_for_prefix_search_exact");
    let td_str = serde_json::to_string(&td).expect(
        "Fail to convert a ciphertext to a string in c_gen_trapdoor_for_prefix_search_exact",
    );
    CPecdkTrapdoor {
        ptr: str2ptr(td_str),
    }
}

#[no_mangle]
pub extern "C" fn c_gen_ciphertext_for_range_search(
    public_key: CPecdkPublicKey,
    region_name: *mut c_char,
    bit_size: c_uint,
    val: c_uint,
) -> CPecdkCiphertext {
    let mut rng = OsRng;
    let pk = match serde_json::from_str::<PublicKey<Bls12>>(&ptr2str(public_key.ptr)) {
        Ok(pk) => pk,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkCiphertext {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let region_name = ptr2str(region_name);
    let bit_size: usize = match bit_size.try_into() {
        Ok(num) => num,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkCiphertext {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let val: u64 = match val.try_into() {
        Ok(num) => num,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkCiphertext {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let ct = gen_ciphertext_for_range_search::<_, Fr, _>(&pk, region_name, bit_size, val, &mut rng)
        .expect("Fail to generate a ciphertext in c_gen_ciphertext_for_range_search");
    let ct_str = serde_json::to_string(&ct)
        .expect("Fail to convert a ciphertext to a string in c_gen_ciphertext_for_range_search");
    CPecdkCiphertext {
        ptr: str2ptr(ct_str),
    }
}

#[no_mangle]
pub extern "C" fn c_gen_trapdoor_for_range_search(
    secret_key: CPecdkSecretKey,
    region_name: *mut c_char,
    min: c_uint,
    max: c_uint,
    bit_size: c_uint,
) -> CPecdkTrapdoor {
    let mut rng = OsRng;
    let sk = match serde_json::from_str::<SecretKey<Bls12>>(&ptr2str(secret_key.ptr)) {
        Ok(sk) => sk,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkTrapdoor {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let region_name = ptr2str(region_name);
    let min: u64 = match min.try_into() {
        Ok(num) => num,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkTrapdoor {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let max: u64 = match max.try_into() {
        Ok(num) => num,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkTrapdoor {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let bit_size: usize = match bit_size.try_into() {
        Ok(num) => num,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkTrapdoor {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let td =
        gen_trapdoor_for_range_search::<_, Fr, _>(&sk, region_name, min, max, bit_size, &mut rng)
            .expect("Fail to generate a trapdoor in c_gen_trapdoor_for_range_search");
    let td_str = serde_json::to_string(&td)
        .expect("Fail to convert a ciphertext to a string in c_gen_trapdoor_for_range_search");
    CPecdkTrapdoor {
        ptr: str2ptr(td_str),
    }
}
