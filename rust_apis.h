#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


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

struct CPeksCiphertext peks_encrypt_keyword(const struct CPeksPublicKey *public_key, char *keyword);

void peks_free_ciphertext(struct CPeksCiphertext ciphertext);

void peks_free_public_key(struct CPeksPublicKey public_key);

void peks_free_secret_key(struct CPeksSecretKey secret_key);

void peks_free_trapdoor(struct CPeksTrapdoor trapdoor);

struct CPeksPublicKey peks_gen_public_key(const struct CPeksSecretKey *secret_key);

struct CPeksSecretKey peks_gen_secret_key(void);

struct CPeksTrapdoor peks_gen_trapdoor(const struct CPeksSecretKey *secret_key, char *keyword);

int peks_test(struct CPeksCiphertext ciphertext, struct CPeksTrapdoor trapdoor);
