#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef struct CPecdkCiphertext {
  char *ptr;
} CPecdkCiphertext;

typedef struct CPecdkPublicKey {
  char *ptr;
} CPecdkPublicKey;

typedef struct CPecdkSecretKey {
  char *ptr;
} CPecdkSecretKey;

typedef struct CPecdkTrapdoor {
  char *ptr;
} CPecdkTrapdoor;

typedef struct CPeksCiphertext {
  char *ptr;
} CPeksCiphertext;

typedef struct CPeksPublicKey {
  char *ptr;
} CPeksPublicKey;

typedef struct CPeksSecretKey {
  char *ptr;
} CPeksSecretKey;

typedef struct CPeksTrapdoor {
  char *ptr;
} CPeksTrapdoor;

struct CPecdkCiphertext pecdk_encrypt_keyword(const struct CPecdkPublicKey *public_key,
                                              const char *keywords,
                                              int num_keyword);

void pecdk_free_ciphertext(struct CPecdkCiphertext ciphertext);

void pecdk_free_public_key(struct CPecdkPublicKey public_key);

void pecdk_free_secret_key(struct CPecdkSecretKey secret_key);

void pecdk_free_trapdoor(struct CPecdkTrapdoor trapdoor);

struct CPecdkPublicKey pecdk_gen_public_key(const struct CPecdkSecretKey *secret_key);

struct CPecdkSecretKey pecdk_gen_secret_key(int num_keyword);

struct CPecdkTrapdoor pecdk_gen_trapdoor(const struct CPecdkSecretKey *secret_key,
                                         const char *keywords,
                                         int num_keyword,
                                         int sym);

int pecdk_test(struct CPecdkCiphertext ciphertext, struct CPecdkTrapdoor trapdoor);

struct CPeksCiphertext peks_encrypt_keyword(const struct CPeksPublicKey *public_key, char *keyword);

void peks_free_ciphertext(struct CPeksCiphertext ciphertext);

void peks_free_public_key(struct CPeksPublicKey public_key);

void peks_free_secret_key(struct CPeksSecretKey secret_key);

void peks_free_trapdoor(struct CPeksTrapdoor trapdoor);

struct CPeksPublicKey peks_gen_public_key(const struct CPeksSecretKey *secret_key);

struct CPeksSecretKey peks_gen_secret_key(void);

struct CPeksTrapdoor peks_gen_trapdoor(const struct CPeksSecretKey *secret_key, char *keyword);

int peks_test(struct CPeksCiphertext ciphertext, struct CPeksTrapdoor trapdoor);
