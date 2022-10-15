use crate::c_utils::*;
use crate::peks::*;
use errno::{errno, set_errno, Errno};
use paired::bls12_381::Bls12;
use rand_core::OsRng;
use std::ffi::*;
use std::marker::PhantomData;
use std::mem;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::slice;
use std::str::FromStr;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CPeksSecretKey {
    ptr: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CPeksPublicKey {
    ptr: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CPeksCiphertext {
    ptr: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CPeksTrapdoor {
    ptr: *mut c_char,
}

const EINVAL: i32 = 22;

#[no_mangle]
pub extern "C" fn peks_gen_secret_key() -> CPeksSecretKey {
    let mut rng = OsRng;
    let sk = SecretKey::<Bls12>::gen(&mut rng);
    let sk_str = serde_json::to_string(&sk)
        .expect("Fail to convert a secret key to a string in peks_gen_secret_key");
    CPeksSecretKey {
        ptr: str2ptr(sk_str),
    }
}

#[no_mangle]
pub extern "C" fn peks_gen_public_key(secret_key: &CPeksSecretKey) -> CPeksPublicKey {
    let mut rng = OsRng;
    let sk = match serde_json::from_str::<SecretKey<Bls12>>(&ptr2str(secret_key.ptr)) {
        Ok(sk) => sk,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPeksPublicKey {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let pk = sk.into_public_key(&mut rng);
    let pk_str = serde_json::to_string(&pk)
        .expect("Fail to convert a public key to a string in peks_gen_public_key");
    CPeksPublicKey {
        ptr: str2ptr(pk_str),
    }
}

#[no_mangle]
pub extern "C" fn peks_encrypt_keyword(
    public_key: &CPeksPublicKey,
    keyword: *mut c_char,
) -> CPeksCiphertext {
    let mut rng = OsRng;
    let pk = match serde_json::from_str::<PublicKey<Bls12>>(&ptr2str(public_key.ptr)) {
        Ok(pk) => pk,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPeksCiphertext {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let keyword = ptr2str(keyword).as_bytes();
    let ct = pk
        .encrypt(keyword, &mut rng)
        .expect("Fail to generate a ciphertext in peks_encrypt_keyword");
    let ct_str = serde_json::to_string(&ct)
        .expect("Fail to convert a ciphertext to a string in peks_encrypt_keyword");
    CPeksCiphertext {
        ptr: str2ptr(ct_str),
    }
}

#[no_mangle]
pub extern "C" fn peks_gen_trapdoor(
    secret_key: &CPeksSecretKey,
    keyword: *mut c_char,
) -> CPeksTrapdoor {
    let sk = match serde_json::from_str::<SecretKey<Bls12>>(&ptr2str(secret_key.ptr)) {
        Ok(sk) => sk,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPeksTrapdoor {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let keyword = ptr2str(keyword).as_bytes();
    let td = sk.gen_trapdoor(keyword);
    let td_str = serde_json::to_string(&td)
        .expect("Fail to convert a trapdoor to a string in peks_gen_trapdoor");
    CPeksTrapdoor {
        ptr: str2ptr(td_str),
    }
}

#[no_mangle]
pub extern "C" fn peks_test(ciphertext: CPeksCiphertext, trapdoor: CPeksTrapdoor) -> c_int {
    let ct = match serde_json::from_str::<Ciphertext<Bls12>>(&ptr2str(ciphertext.ptr)) {
        Ok(ct) => ct,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return -1;
        }
    };
    let td = match serde_json::from_str::<Trapdoor<Bls12>>(&ptr2str(trapdoor.ptr)) {
        Ok(td) => td,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return -1;
        }
    };
    let tested = td
        .test(&ct)
        .expect("Fail to test the ciphertext with the trapdoor in peks_test");
    if tested {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn peks_free_secret_key(secret_key: CPeksSecretKey) {
    drop_ptr(secret_key.ptr);
}

#[no_mangle]
pub extern "C" fn peks_free_public_key(public_key: CPeksPublicKey) {
    drop_ptr(public_key.ptr);
}

#[no_mangle]
pub extern "C" fn peks_free_ciphertext(ciphertext: CPeksCiphertext) {
    drop_ptr(ciphertext.ptr);
}

#[no_mangle]
pub extern "C" fn peks_free_trapdoor(trapdoor: CPeksTrapdoor) {
    drop_ptr(trapdoor.ptr);
}
