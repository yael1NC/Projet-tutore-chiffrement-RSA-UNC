#include "rsa.h"

void generate_random_nbr(mpz_t result) {
    char buf[256]; // creation d'un buffer avec 256 octets, donc 2048 bits
    randombytes_buf(buf, 256); // Nombre aleatoire dedans

    mpz_import(result, 256, 1, 1, 1, 0, buf);

    sodium_memzero(buf, 256);
}

int is_first(mpz_t n) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL));

    if(mpz_cmp_ui(n, 2) < 0) return 0;
    if(mpz_even_p(n)) return 0;

    const int k = 25; // Important

    for(int i = 0; i < k; i++) {
        mpz_t a;
        mpz_init(a);

        mpz_urandomm(a, state, n);

        if (miller_rabin(n, a)) {
            mpz_clear(a);
            return 0;
        }
        mpz_clear(a);
    }
    return 1;
}

int miller_rabin(mpz_t n, mpz_t a) {
    mpz_t d, s_val;
    mpz_init(d);
    mpz_init(s_val);
    mpz_sub_ui(d, n, 1); // d = n - 1

    unsigned long s = 0;
    while (mpz_even_p(d)) {
        mpz_div_ui(d, d, 2);
        s++;
    }
    mpz_set_ui(s_val, s);

    mpz_t x;
    mpz_init(x);
    mpz_powm_sec(x, a, d, n); // x = a^d mod n

    if (mpz_cmp_ui(x, 1) == 0 || mpz_cmp(x, mpz_sub_ui(x, n, 1)) == 0) {
        mpz_clear(d);
        mpz_clear(s_val);
        mpz_clear(x);
        return 0; // Probablement premier
    }

    for (unsigned long i = 0; i < s; i++) {
        mpz_powm_ui(x, x, 2, n); // x = x^2 mod n
        if (mpz_cmp(x, mpz_sub_ui(x, n, 1)) == 0) {
            mpz_clear(d);
            mpz_clear(s_val);
            mpz_clear(x);
            return 0; // Probablement premier
        }
    }

    mpz_clear(d);
    mpz_clear(s_val);
    mpz_clear(x);
    return 1; // Composé
}

void generate_prime_nbr(mpz_t prime) {
    do {
        generate_random_nbr(prime);
    } while (!is_first(prime));
}


void generate_rsa_keys(char* n_hex_out, char* d_hex_out, size_t buffer_size) {
    keys key; // Utilisation de la structure interne
    mpz_init(key.n);
    mpz_init_set_ui(key.e, 65537); // Exposant public standard
    mpz_init(key.d);
    mpz_init(key.p);
    mpz_init(key.q);

    // Générer p et q, deux grands nombres premiers
    generate_prime_nbr(key.p);
    generate_prime_nbr(key.q);

    // Assurer que p et q sont différents pour éviter des faiblesses
    while (mpz_cmp(key.p, key.q) == 0) {
        generate_prime_nbr(key.q);
    }

    // Calcul de n = p * q
    mpz_mul(key.n, key.p, key.q);

    // Calcul de phi(n) = (p-1)(q-1)
    mpz_t p_minus_1, q_minus_1, phi;
    mpz_init(p_minus_1);
    mpz_init(q_minus_1);
    mpz_init(phi);

    mpz_sub_ui(p_minus_1, key.p, 1);
    mpz_sub_ui(q_minus_1, key.q, 1);
    mpz_mul(phi, p_minus_1, q_minus_1);

    // Calcul de d, l'inverse modulaire de e sous phi(n)
    // d = e^-1 mod phi(n)
    mpz_invert(key.d, key.e, phi);

    // Conversion en chaînes hexadécimales
    char* n_str = mpz_get_str(NULL, 16, key.n);
    char* d_str = mpz_get_str(NULL, 16, key.d);

    // Copie dans les buffers de sortie
    strncpy(n_hex_out, n_str, buffer_size - 1);
    n_hex_out[buffer_size - 1] = '\0';
    strncpy(d_hex_out, d_str, buffer_size - 1);
    d_hex_out[buffer_size - 1] = '\0';

    // Libération de la mémoire GMP et des chaînes temporaires
    free(n_str);
    free(d_str);
    mpz_clear(p_minus_1);
    mpz_clear(q_minus_1);
    mpz_clear(phi);
    mpz_clear(key.n);
    mpz_clear(key.e);
    mpz_clear(key.d);
    mpz_clear(key.p);
    mpz_clear(key.q);
}


void rsa_encrypt_string(const char* non_encrypt_hex, const char* e_hex, const char* n_hex, char* encrypt_message_hex_out, size_t buffer_size) {
    mpz_t m, c, e_mpz, n_mpz;

    mpz_init(m);
    mpz_init(c);
    mpz_init(e_mpz);
    mpz_init(n_mpz);

    mpz_set_str(e_mpz, e_hex, 16);
    mpz_set_str(n_mpz, n_hex, 16);

    // Convertit la chaîne hexadécimale du message en mpz_t
    mpz_set_str(m, non_encrypt_hex, 16);

    // c = m^e mod n
    mpz_powm_sec(c, m, e_mpz, n_mpz);

    char* hex = mpz_get_str(NULL, 16, c);
    strncpy(encrypt_message_hex_out, hex, buffer_size - 1);
    encrypt_message_hex_out[buffer_size - 1] = '\0';

    free(hex);
    mpz_clear(m);
    mpz_clear(c);
    mpz_clear(e_mpz);
    mpz_clear(n_mpz);
}

void rsa_decrypt_string(const char* encrypt_message_hex, const char* d_hex, const char* n_hex, char* non_encrypt_hex_out, size_t buffer_size) {
    mpz_t c, m, d_mpz, n_mpz;

    // Init variables
    mpz_init(c);
    mpz_init(m);
    mpz_init(d_mpz);
    mpz_init(n_mpz);

    // Convertit clés et message chiffré en mpz
    mpz_set_str(c, encrypt_message_hex, 16);
    mpz_set_str(d_mpz, d_hex, 16);
    mpz_set_str(n_mpz, n_hex, 16);

    // Déchiffrement : m = c^d mod n
    mpz_powm_sec(m, c, d_mpz, n_mpz);

    // Convertit m (entier clair) en chaîne hexadécimale
    char* hex = mpz_get_str(NULL, 16, m);
    strncpy(non_encrypt_hex_out, hex, buffer_size - 1);
    non_encrypt_hex_out[buffer_size - 1] = '\0';

    free(hex);
    mpz_clear(c);
    mpz_clear(m);
    mpz_clear(d_mpz);
    mpz_clear(n_mpz);
}

void rsa_sign_string(const char* message_hash_hex, const char* d_hex, const char* n_hex, char* signature_hex_out, size_t buffer_size) {
    mpz_t message_hash_mpz, signature_mpz, d_mpz, n_mpz;

    mpz_init(message_hash_mpz);
    mpz_init(signature_mpz);
    mpz_init(d_mpz);
    mpz_init(n_mpz);

    mpz_set_str(message_hash_mpz, message_hash_hex, 16);
    mpz_set_str(d_mpz, d_hex, 16);
    mpz_set_str(n_mpz, n_hex, 16);

    // La signature est s = H(m)^d mod n
    mpz_powm_sec(signature_mpz, message_hash_mpz, d_mpz, n_mpz);

    char* hex = mpz_get_str(NULL, 16, signature_mpz);
    strncpy(signature_hex_out, hex, buffer_size - 1);
    signature_hex_out[buffer_size - 1] = '\0';

    free(hex);
    mpz_clear(message_hash_mpz);
    mpz_clear(signature_mpz);
    mpz_clear(d_mpz);
    mpz_clear(n_mpz);
}

int rsa_verify_string(const char* message_hash_hex, const char* signature_hex, const char* e_hex, const char* n_hex) {
    mpz_t message_hash_mpz, signature_mpz, e_mpz, n_mpz, recovered_hash;

    mpz_init(message_hash_mpz);
    mpz_init(signature_mpz);
    mpz_init(e_mpz);
    mpz_init(n_mpz);
    mpz_init(recovered_hash);

    mpz_set_str(message_hash_mpz, message_hash_hex, 16);
    mpz_set_str(signature_mpz, signature_hex, 16);
    mpz_set_str(e_mpz, e_hex, 16);
    mpz_set_str(n_mpz, n_hex, 16);

    // Calculer H'(m) = s^e mod n
    mpz_powm_sec(recovered_hash, signature_mpz, e_mpz, n_mpz);

    // Comparer H'(m) avec H(m)
    int result = (mpz_cmp(recovered_hash, message_hash_mpz) == 0);

    mpz_clear(message_hash_mpz);
    mpz_clear(signature_mpz);
    mpz_clear(e_mpz);
    mpz_clear(n_mpz);
    mpz_clear(recovered_hash);

    return result;
}