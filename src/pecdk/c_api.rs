use crate::c_utils::*;
use crate::pecdk::*;
use core::slice;
use errno::{set_errno, Errno};
use paired::bls12_381::{Bls12, Fr};
use rand_core::OsRng;
use std::os::raw::c_char;
use std::os::raw::{c_int, c_uint};

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CPecdkSecretKey {
    pub(crate) ptr: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CPecdkPublicKey {
    pub(crate) ptr: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CPecdkCiphertext {
    pub(crate) ptr: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CPecdkTrapdoor {
    pub(crate) ptr: *mut c_char,
}

pub(crate) const EINVAL: i32 = 22;

#[no_mangle]
pub extern "C" fn pecdkGenSecretKey(num_keyword: usize) -> CPecdkSecretKey {
    let mut rng = OsRng;
    let sk = SecretKey::<Bls12>::gen(&mut rng, num_keyword);
    let sk_str = serde_json::to_string(&sk)
        .expect("Fail to convert a secret key to a string in pecdk_gen_secret_key");
    CPecdkSecretKey {
        ptr: str2ptr(sk_str),
    }
}

#[no_mangle]
pub extern "C" fn pecdkGenPublicKey(secret_key: CPecdkSecretKey) -> CPecdkPublicKey {
    let mut rng = OsRng;
    let sk = match serde_json::from_str::<SecretKey<Bls12>>(&ptr2str(secret_key.ptr)) {
        Ok(sk) => sk,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkPublicKey {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let pk = sk.into_public_key(&mut rng);
    let pk_str = serde_json::to_string(&pk)
        .expect("Fail to convert a public key to a string in pecdk_gen_public_key");
    CPecdkPublicKey {
        ptr: str2ptr(pk_str),
    }
}

#[no_mangle]
pub extern "C" fn pecdkEncryptKeyword(
    public_key: CPecdkPublicKey,
    keywords: *mut *mut c_char,
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
    let num_keyword = pk.num_keyword();
    let keyword_slice = unsafe { slice::from_raw_parts(keywords, num_keyword) };
    let keywords = keyword_slice
        .into_iter()
        .map(|keyword| ptr2str(*keyword).as_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>();
    let ct = pk
        .encrypt::<OsRng, Fr>(keywords, &mut rng)
        .expect("Fail to generate a ciphertext in peks_encrypt_keyword");
    let ct_str = serde_json::to_string(&ct)
        .expect("Fail to convert a ciphertext to a string in pecdk_encrypt_keyword");
    CPecdkCiphertext {
        ptr: str2ptr(ct_str),
    }
}

#[no_mangle]
pub extern "C" fn pecdkGenTrapdoor(
    secret_key: CPecdkSecretKey,
    keywords: *mut *mut c_char,
    num_keyword: usize,
    sym: c_int,
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
    let num_keyword = match num_keyword.try_into() {
        Ok(num) => num,
        Err(_) => {
            set_errno(Errno(EINVAL));
            return CPecdkTrapdoor {
                ptr: str2ptr(String::new()),
            };
        }
    };
    let keyword_slice = unsafe { slice::from_raw_parts(keywords, num_keyword) };
    let keywords = keyword_slice
        .into_iter()
        .map(|keyword| ptr2str(*keyword).as_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>();
    let sym = match sym {
        0 => SearchSym::AND,
        _ => SearchSym::OR,
    };
    let td = sk
        .gen_trapdoor::<OsRng, Fr>(keywords, sym, &mut rng)
        .expect("Fail to generate a trapdoor in pecdk_gen_trapdoor");
    let td_str = serde_json::to_string(&td)
        .expect("Fail to convert a trapdoor to a string in peks_gen_trapdoor");
    CPecdkTrapdoor {
        ptr: str2ptr(td_str),
    }
}

#[no_mangle]
pub extern "C" fn pecdkTest(ciphertext: CPecdkCiphertext, trapdoor: CPecdkTrapdoor) -> c_int {
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
pub extern "C" fn pecdkFreeSecretKey(secret_key: CPecdkSecretKey) {
    drop_ptr(secret_key.ptr);
}

#[no_mangle]
pub extern "C" fn pecdkFreePublicKey(public_key: CPecdkPublicKey) {
    drop_ptr(public_key.ptr);
}

#[no_mangle]
pub extern "C" fn pecdkFreeCiphertext(ciphertext: CPecdkCiphertext) {
    drop_ptr(ciphertext.ptr);
}

#[no_mangle]
pub extern "C" fn pecdkFreeTrapdoor(trapdoor: CPecdkTrapdoor) {
    drop_ptr(trapdoor.ptr);
}
