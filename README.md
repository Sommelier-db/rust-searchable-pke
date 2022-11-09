# Rust-Searchable-PKE
**Rust implementation of Public-Key Searchable Encryption.**

## Disclaimer
DO NOT USE THIS LIBRARY IN PRODUCTION. At this point, this is under development. It has known and unknown bugs and security flaws.

## Features
This library provides implemenations of various public-key searchable encryption (PKSE) schemes. 
PKSE has the same features as standard public-key encryption schemes, e.g., RSA encryption scheme, except that **the secret key holder can allow a third party to test whether the encrypted data satisfies some search criteria, without revealing the data and the search criteria**.
Our library allows you to use its features without understanding how it works.

Specifically, the following schemes are supported.

1. Public-key Encryption with Keyword Search (PEKS)

Public-key encryption with keyword search (PEKS) is the first and the simplest PKSE scheme [1]. It can search only for keyword encryptions that exactly match the given keywords. Its APIs are available [here](https://github.com/SoraSuegami/rust-searchable-pke/tree/master/src/peks).

2. Public-key Encryption with Conjunctive and Disjunctive Keyword search (PECDK)

Public-key encryption with conjunctive and disjunctive keyword search (PECDK) encrypts multiple keywords into one ciphertext and supports conjunctive and disjunctive of keywords as search criteria [2]. For example, we consider an encryptions of keywords "Alice, Emergency, Accident". It matches the conjunction of keywords "Alice, Emergency" and the disjunction of keywords "Alice, Bob".
Our current implementation follows the scheme proposed in [2]. Its APIs are available [here](https://github.com/SoraSuegami/rust-searchable-pke/tree/master/src/pecdk).

Furthermore, our library provides expressive search criteria as below. Notably, all of them are implemented by changing how to construct the keywords in the PECDK scheme.

- Field And/OR Search: 
it encrypts multiple pairs of field name and value and retrieves their encryption that includes all/one of the specified pairs in the AND/OR search. 
- Range Search:
it encrypts an unsigned integer and retrieves the encryption whose integer is within the specified range.
- Prefix Search:
it encrypts a string and retrieves the encryption whose string has the specified prefix.

## C APIs
Our library also provides C apis for the above functions.

## Requirement
- rustc 1.65.0-nightly (0b79f758c 2022-08-18)
- cargo 1.65.0-nightly (9809f8ff3 2022-08-16)
- cbindgen 0.24.3

## Installation and Build
You can install and build our library with the following commands.
```bash
git clone https://github.com/SoraSuegami/rust-searchable-pke.git
cd rust-searchable-pke
./build.sh
```

## Usage
You can open the API specification by executing the following command under the rust-searchable-pke directory.
```bash
cargo doc --open
```

## Test
You can run the tests by executing the following command under the rust-searchable-pke directory.
```bash
cargo test
```

## Authors
- Sora Suegami

## License
This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/SoraSuegami/rust-searchable-pke/tree/master/LICENSE.md) file for details


## Acknowledgments
We referred to Python and Rust implementations of polynomial computations over finite field in the ZK-STARK libraries developed by [vitalik](https://github.com/ethereum/research/blob/master/mimc_stark/poly_utils.py) and [hrmk1o3](https://github.com/InternetMaximalism/stark-pure-rust/blob/develop/packages/fri/src/poly_utils.rs).

Our range search functions are developed following the scheme of Range Queries in Section 3 of [3].

## Reference
1. Boneh, D., Crescenzo, G. D., Ostrovsky, R., & Persiano, G. (2004, May). Public key encryption with keyword search. In International conference on the theory and applications of cryptographic techniques (pp. 506-522). Springer, Berlin, Heidelberg.
2. Zhang, Y., Li, Y., & Wang, Y. (2019). Secure and efficient searchable public key encryption for resource constrained environment based on pairings under prime order group. Security and Communication Networks, 2019.
3. Faber, S., Jarecki, S., Krawczyk, H., Nguyen, Q., Rosu, M., & Steiner, M. (2015, September). Rich queries on encrypted data: Beyond exact matches. In European symposium on research in computer security (pp. 123-145). Springer, Cham.