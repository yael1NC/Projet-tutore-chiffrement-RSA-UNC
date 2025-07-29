#ifndef RSA_H
#define RSA_H

#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sodium.h>
#include <stddef.h>
#include <string.h>

// Structure utilisée en interne pour la génération de clés
typedef struct {
    mpz_t n;
    mpz_t e;
    mpz_t d;
    mpz_t p;
    mpz_t q;
} keys;

// Fonctions de base pour les nombres premiers
void generate_random_nbr(mpz_t result);
int is_first(mpz_t n);
int miller_rabin(mpz_t n, mpz_t a);
void generate_prime_nbr(mpz_t prime);

// Nouvelle API pour la génération de clés (retourne des chaînes hex)
void generate_rsa_keys(char* n_hex_out, char* d_hex_out, size_t buffer_size);

// Nouvelle API pour le chiffrement/déchiffrement (prend/retourne des chaînes hex)
void rsa_encrypt_string(const char* non_encrypt_hex, const char* e_hex, const char* n_hex, char* encrypt_message_hex_out, size_t buffer_size);
void rsa_decrypt_string(const char* encrypt_message_hex, const char* d_hex, const char* n_hex, char* non_encrypt_hex_out, size_t buffer_size);

// API pour la signature/vérification (prend/retourne des chaînes hex)
void rsa_sign_string(const char* message_hash_hex, const char* d_hex, const char* n_hex, char* signature_hex_out, size_t buffer_size);
int rsa_verify_string(const char* message_hash_hex, const char* signature_hex, const char* e_hex, const char* n_hex);

#endif // RSA_H