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

typedef struct CPecdkTrapdoor {
  char *ptr;
} CPecdkTrapdoor;

typedef struct CPecdkSecretKey {
  char *ptr;
} CPecdkSecretKey;

struct CPecdkCiphertext genCiphertextForFieldSearch(struct CPecdkPublicKey public_key,
                                                    char *region_name,
                                                    size_t num_fields,
                                                    char **fields,
                                                    char **vals);

struct CPecdkCiphertext genCiphertextForPrefixSearch(struct CPecdkPublicKey public_key,
                                                     char *region_name,
                                                     char *string);

struct CPecdkCiphertext genCiphertextForRangeSearch(struct CPecdkPublicKey public_key,
                                                    char *region_name,
                                                    size_t bit_size,
                                                    unsigned int val);

struct CPecdkTrapdoor genTrapdoorForFieldAndSearch(struct CPecdkSecretKey secret_key,
                                                   char *region_name,
                                                   size_t num_fields,
                                                   char **fields,
                                                   char **vals);

struct CPecdkTrapdoor genTrapdoorForFieldOrSearch(struct CPecdkSecretKey secret_key,
                                                  char *region_name,
                                                  size_t num_fields,
                                                  char **fields,
                                                  char **vals);

struct CPecdkTrapdoor genTrapdoorForPrefixSearch(struct CPecdkSecretKey secret_key,
                                                 char *region_name,
                                                 char *prefix);

struct CPecdkTrapdoor genTrapdoorForPrefixSearchExact(struct CPecdkSecretKey secret_key,
                                                      char *region_name,
                                                      char *string);

struct CPecdkTrapdoor genTrapdoorForRangeSearch(struct CPecdkSecretKey secret_key,
                                                char *region_name,
                                                unsigned int min,
                                                unsigned int max,
                                                size_t bit_size);

struct CPecdkCiphertext pecdkEncryptKeyword(struct CPecdkPublicKey public_key, char **keywords);

void pecdkFreeCiphertext(struct CPecdkCiphertext ciphertext);

void pecdkFreePublicKey(struct CPecdkPublicKey public_key);

void pecdkFreeSecretKey(struct CPecdkSecretKey secret_key);

void pecdkFreeTrapdoor(struct CPecdkTrapdoor trapdoor);

struct CPecdkPublicKey pecdkGenPublicKey(struct CPecdkSecretKey secret_key);

struct CPecdkSecretKey pecdkGenSecretKey(size_t num_keyword);

struct CPecdkTrapdoor pecdkGenTrapdoor(struct CPecdkSecretKey secret_key,
                                       char **keywords,
                                       size_t num_keyword,
                                       int sym);

int pecdkTest(struct CPecdkCiphertext ciphertext, struct CPecdkTrapdoor trapdoor);
