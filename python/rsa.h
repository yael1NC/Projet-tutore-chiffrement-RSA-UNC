#ifndef RSA_H
#define RSA_H

#include <gmp.h>
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

//Implémentation de Base
void generate_random_nbr(mpz_t result);
int is_prime(mpz_t n);
int miller_rabin(mpz_t n, mpz_t a);
void generate_prime_nbr(mpz_t prime);
void generate_rsa_keys(char* n_hex_out, char* d_hex_out, size_t buffer_size);

// Fonction de chiffrement
void rsa_encrypt_string(const char* non_encrypt, const char* e_hex, const char* n_hex, char* encrypt_message_hex, size_t buffer_size, int algo_choice);

// Fonction de déchiffrement 
void rsa_decrypt_string(const char* encrypt_message_hex, const char* d_hex, const char* n_hex, char* non_encrypt, size_t buffer_size, int algo_choice);

// Algorithmes d'exponentiation
void square_and_multiply(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n);
void square_and_multiply_always(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n);
void montgomery_ladder(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n);
void semi_interleaved_ladder(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n);

void extended_euclidean(mpz_t gcd, mpz_t u, const mpz_t a, const mpz_t n);
void fully_interleaved_ladder(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n);

#endif 