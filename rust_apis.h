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

struct CPeksCiphertext encrypt_keyword(const struct CPeksPublicKey *public_key, char *keyword);

struct CPeksPublicKey gen_public_key(const struct CPeksSecretKey *secret_key);

struct CPeksSecretKey gen_secret_key(void);

struct CPeksTrapdoor gen_trapdoor(const struct CPeksSecretKey *secret_key, char *keyword);

bool test(struct CPeksCiphertext ciphertext, struct CPeksTrapdoor trapdoor);
