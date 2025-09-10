#include "rsa.h"

        
void generate_random_nbr(mpz_t result) {
    char buf[512]; // creation d'un buffer avec 512 octets, donc 4096 bits
    randombytes_buf(buf, (512)); // Nombre aleatoire dedans

    mpz_import(result, 512, 1, 1, 1, 0, buf); 

    sodium_memzero(buf, 512);
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
    int s = 0;

    mpz_t d;
    mpz_init_set(d, n);
    mpz_sub_ui(d, d, 1);

    mpz_t b;
    mpz_init(b);
    mpz_set_ui(b, 2);

    mpz_t passage;
    mpz_init(passage);

    mpz_mod(passage, d, b);

    while( (mpz_cmp_ui(passage, 0)) == 0 ) {

        mpz_tdiv_q(d, d, b);
        s++;

        mpz_mod(passage, d, b);
    }
    
    mpz_t x;
    mpz_init(x);

    mpz_t nbis;
    mpz_init_set(nbis, n);
    mpz_sub_ui(nbis, nbis, 1);

    mpz_powm_sec(x, a, d, n);

    if(mpz_cmp_ui(x, 1) == 0 || mpz_cmp(x, nbis) == 0) return 0;

    for(int i = 0; i<(s-1); i++) {
        mpz_powm_sec(x, x, b, n);
        if(mpz_cmp(x, nbis) == 0) return 0;
    }

    mpz_clear(d); 
    mpz_clear(b);
    mpz_clear(passage);
    mpz_clear(x);
    mpz_clear(nbis);

    return 1;
}

void generate_prime_nbr(mpz_t prime) {
    generate_random_nbr(prime);
    while(!(is_first(prime))) {
        generate_random_nbr(prime);
    }
}

void generate_rsa_keys(char* n_hex_out, char* d_hex_out, size_t buffer_size) {
    mpz_t p, q, n, e, d, phi, pbis, qbis;

    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init_set_ui(e, 65537);
    mpz_init(d);
    mpz_init(phi);
    mpz_init(pbis);
    mpz_init(qbis);

    generate_prime_nbr(p);
    generate_prime_nbr(q);

    // n = p * q
    mpz_mul(n, p, q);

    // phi(n) = (p-1) * (q-1)
    mpz_set(pbis, p);
    mpz_sub_ui(pbis, pbis, 1);
    
    mpz_set(qbis, q);
    mpz_sub_ui(qbis, qbis, 1);
    
    mpz_mul(phi, pbis, qbis);

    // d = e mod phi(n)
    mpz_invert(d, e, phi);

    char* n_str = mpz_get_str(NULL, 16, n);
    char* d_str = mpz_get_str(NULL, 16, d);
        
    strncpy(n_hex_out, n_str, buffer_size - 1);
    strncpy(d_hex_out, d_str, buffer_size - 1);
    n_hex_out[buffer_size - 1] = '\0';
    d_hex_out[buffer_size - 1] = '\0';
        
    free(n_str);
    free(d_str);
    
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(d);
    mpz_clear(phi);
    mpz_clear(pbis);
    mpz_clear(qbis);
}

void rsa_encrypt_string(const char* non_encrypt, const char* e_hex, const char* n_hex, char* encrypt_message_hex, size_t buffer_size) {
    mpz_t m, c, e, n;

    mpz_init(m);
    mpz_init(c);
    mpz_init(e);
    mpz_init(n);

    mpz_set_str(e, e_hex, 16);
    mpz_set_str(n, n_hex, 16);

    
    mpz_import(m, strlen(non_encrypt), 1, 1, 0, 0, non_encrypt);

    // c = m^e mod n
    mpz_powm(c, m, e, n);

    char* hex = mpz_get_str(NULL, 16, c);
    strncpy(encrypt_message_hex, hex, buffer_size - 1);
    encrypt_message_hex[buffer_size - 1] = '\0';

    free(hex);
    mpz_clears(m, c, e, n);
}


void rsa_decrypt_string(const char* encrypt_message_hex, const char* d_hex, const char* n_hex, char* non_encrypt, size_t buffer_size, int algo_choice) {
    mpz_t c, m, d, n;
    mpz_inits(c, m, d, n, NULL);

    mpz_set_str(c, encrypt_message_hex, 16);
    mpz_set_str(d, d_hex, 16);
    mpz_set_str(n, n_hex, 16);

    // Dechiffrement : m = c^d mod n
    // Utilisation d'un switch pour sélectionner l'algorithme
    switch(algo_choice) {
        case 1:
            square_and_multiply(m, c, d, n);
            break;
        case 2:
            square_and_multiply_always(m, c, d, n);
            break;
        case 3:
            montgomery_ladder(m, c, d, n);
            break;
        case 4:
            semi_interleaved_ladder(m, c, d, n);
            break;
        case 5:
            fully_interleaved_ladder(m, c, d, n);
            break;
        default: // Par défaut, utilise la fonction la plus optimisée de GMP
            mpz_powm(m, c, d, n);
            break;
    }

    size_t count;
    void* raw = mpz_export(NULL, &count, 1, 1, 0, 0, m);

    if (count >= buffer_size) count = buffer_size - 1;

    memcpy(non_encrypt, raw, count);
    non_encrypt[count] = '\0';

    free(raw);
    mpz_clears(c, m, d, n, NULL);
}


void square_and_multiply(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n) {
    mpz_t x, temp;
    mpz_inits(x, temp, NULL);

    mpz_set_ui(x, 1);

    size_t bit_length = mpz_sizeinbase(k, 2);

    // CORRECTION: Utilisez size_t au lieu de long, et gérez le underflow
    for (size_t i = bit_length; i > 0; i--) {
        size_t bit_index = i - 1; // Décalage pour avoir l'index correct
        
        // x = x^2 mod n
        mpz_mul(temp, x, x);
        mpz_mod(x, temp, n);

        // si k[bit_index] = 1 alors x = a*x mod n
        if (mpz_tstbit(k, bit_index)) {
            mpz_mul(temp, x, a);
            mpz_mod(x, temp, n);
        }
    }

    mpz_set(result, x);
    mpz_clears(x, temp, NULL);
}

void square_and_multiply_always(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n) {
    mpz_t x, y, temp;
    mpz_inits(x, y, temp, NULL);

    mpz_set_ui(x, 1);

    size_t bit_length = mpz_sizeinbase(k, 2);

    // CORRECTION: Même problème ici
    for (size_t i = bit_length; i > 0; i--) {
        size_t bit_index = i - 1;
        
        mpz_mul(temp, x, x);
        mpz_mod(x, temp, n);

        mpz_mul(temp, x, a);
        mpz_mod(temp, temp, n); // AJOUT: il faut faire le modulo ici aussi

        if (mpz_tstbit(k, bit_index)) {
            mpz_set(x, temp); 
        } else {
            mpz_set(y, temp); 
        }
    }

    mpz_set(result, x);
    mpz_clears(x, y, temp, NULL);
}

void montgomery_ladder(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n) {
    mpz_t x, y, t1, t2, t3;
    mpz_inits(x, y, t1, t2, t3, NULL);

    mpz_set_ui(x, 1);
    mpz_mod(y, a, n);

    size_t bit_length = mpz_sizeinbase(k, 2);

    // CORRECTION: Même problème ici
    for (size_t i = bit_length; i > 0; i--) {
        size_t bit_index = i - 1;
        int bit = mpz_tstbit(k, bit_index);

        mpz_mul(t1, x, y); 
        mpz_mod(t1, t1, n); // x*y mod n

        mpz_mul(t2, x, x); 
        mpz_mod(t2, t2, n);// x^2 mod n
        
        mpz_mul(t3, y, y); 
        mpz_mod(t3, t3, n); // y^2 mod n

        if (bit) {
            //x = x*y, y = y^2
            mpz_set(x, t1);
            mpz_set(y, t3);
        } else {
            //y = x*y, x = x^2
            mpz_set(y, t1);
            mpz_set(x, t2);
        }
    }

    mpz_set(result, x);
    mpz_clears(x, y, t1, t2, t3, NULL);
}

void semi_interleaved_ladder(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n) {
    mpz_t x, y, m, c1, c2, z, temp1, temp2;
    mpz_inits(x, y, m, c1, c2, z, temp1, temp2, NULL);

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL));

    // 1: x ← 1
    mpz_set_ui(x, 1);
    // 2: y ← a mod n
    mpz_mod(y, a, n);
    
    // 3: m ← random([0, n − 1])
    mpz_urandomm(m, state, n);
    
    // 4: c1 ← ma mod n
    mpz_mul(c1, m, a);
    mpz_mod(c1, c1, n);

    // 5: c2 ← 1 − (c1a + m) mod n
    mpz_mul(temp1, c1, a);      // c1*a
    mpz_add(temp1, temp1, m);     // c1*a + m
    mpz_ui_sub(c2, 1, temp1);   // 1 - (c1*a + m)
    mpz_mod(c2, c2, n);           // mod n

    size_t bit_length = mpz_sizeinbase(k, 2);
    
    // CORRECTION: Même problème ici
    for (size_t i = bit_length; i > 0; i--) {
        size_t bit_index = i - 1;
        
        if (mpz_tstbit(k, bit_index)) { // k[bit_index] == 1
            // z ← y² mod n
            mpz_mul(z, y, y);
            mpz_mod(z, z, n);
            // x ← c1(x² + z) + c2xy mod n
            mpz_mul(temp1, x, x);       // x²
            mpz_add(temp1, temp1, z);   // x² + z
            mpz_mul(temp1, temp1, c1);  // c1(x² + z)
            mpz_mul(temp2, c2, x);      // c2*x
            mpz_mul(temp2, temp2, y);   // c2*x*y
            mpz_add(x, temp1, temp2);   // addition finale
            mpz_mod(x, x, n);
            // y ← z
            mpz_set(y, z);
        } else { // k[bit_index] == 0
            // z ← x² mod n
            mpz_mul(z, x, x);
            mpz_mod(z, z, n);
            // y ← c1(y² + z) + c2yx mod n
            mpz_mul(temp1, y, y);       // y²
            mpz_add(temp1, temp1, z);   // y² + z
            mpz_mul(temp1, temp1, c1);  // c1(y² + z)
            mpz_mul(temp2, c2, y);      // c2*y
            mpz_mul(temp2, temp2, x);   // c2*y*x
            mpz_add(y, temp1, temp2);   // addition finale
            mpz_mod(y, y, n);
            // x ← z
            mpz_set(x, z);
        }
    }

    mpz_set(result, x);

    mpz_clears(x, y, m, c1, c2, z, temp1, temp2, NULL);
    gmp_randclear(state);
}

void fully_interleaved_ladder(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n) {
    mpz_t l, v0, v2, v3, u1, u2, u3, c0, c1, c2, c3, x, y, z, temp;
    mpz_inits(l, v0, v2, v3, u1, u2, u3, c0, c1, c2, c3, x, y, z, temp, NULL);

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL));

    // Pré-computation pour trouver une constante l valide
    mpz_t n_minus_2;
    mpz_init_set(n_minus_2, n);
    mpz_sub_ui(n_minus_2, n_minus_2, 2);

    int l_is_valid = 0;
    while (!l_is_valid) {
        mpz_urandomm(l, state, n_minus_2); // l dans [0, n-3]
        mpz_add_ui(l, l, 2);               // l dans [2, n-1]
        
        if (mpz_cmp(l, a) == 0) continue; // l ne doit pas être égal à a

        int inv1 = mpz_invert(u1, l, n); // inv(l)
        
        mpz_mul(v2, l, l);
        mpz_sub_ui(v2, v2, 1);
        int inv2 = mpz_invert(u2, v2, n); // inv(l^2 - 1)

        mpz_mul(v3, v2, l); // l^3 - l
        mpz_add_ui(v3, v3, 1); // l^3
        mpz_sub(v3, v3, a); // l^3 - a
        int inv3 = mpz_invert(u3, v3, n); // inv(l^3 - a)

        if (inv1 && inv2 && inv3) {
            l_is_valid = 1;
        }
    }
    mpz_clear(n_minus_2);

    // Calcul des constantes c0, c1, c2, c3
    mpz_sub(v0, l, a); // l - a

    mpz_mul(c0, u1, u2);
    mpz_mul(c0, c0, v3);
    mpz_mod(c0, c0, n);

    mpz_neg(c1, v0);
    mpz_mul(c1, c1, u2);
    mpz_mod(c1, c1, n);

    mpz_mul(c2, a, v2);
    mpz_mul(c2, c2, u3);
    mpz_mod(c2, c2, n);
    
    mpz_mul(c3, l, v0);
    mpz_mul(c3, c3, u3);
    mpz_mod(c3, c3, n);

    // Initialisation
    mpz_set_ui(x, 1);
    mpz_set(y, l);

    // Boucle principale - CORRECTION: Même problème ici
    size_t bit_length = mpz_sizeinbase(k, 2);
    for (size_t i = bit_length; i > 0; i--) {
        size_t bit_index = i - 1;
        
        if (mpz_tstbit(k, bit_index)) { // k[bit_index] == 1
            mpz_mul(z, y, y);
            mpz_mod(z, z, n); // z = y^2
            
            // x <- c0*x*y + c1*z
            mpz_mul(temp, c0, x);
            mpz_mul(temp, temp, y);
            mpz_mul(x, c1, z);
            mpz_add(x, x, temp);
            mpz_mod(x, x, n);

            // y <- c2*z + c3*x (utilise le nouveau x)
            mpz_mul(temp, c2, z);
            mpz_mul(y, c3, x);
            mpz_add(y, y, temp);
            mpz_mod(y, y, n);

        } else { // k[bit_index] == 0
            mpz_mul(z, x, x);
            mpz_mod(z, z, n); // z = x^2

            // y <- c0*y*x + c1*z
            mpz_mul(temp, c0, y);
            mpz_mul(temp, temp, x);
            mpz_mul(y, c1, z);
            mpz_add(y, y, temp);
            mpz_mod(y, y, n);
            
            // x <- c2*z + c3*y (utilise le nouveau y)
            mpz_mul(temp, c2, z);
            mpz_mul(x, c3, y);
            mpz_add(x, x, temp);
            mpz_mod(x, x, n);
        }
    }

    mpz_set(result, x);
    
    mpz_clears(l, v0, v2, v3, u1, u2, u3, c0, c1, c2, c3, x, y, z, temp, NULL);
    gmp_randclear(state);
}

// comment verifier que p et q premier ?
// verifier que p et q pas pair par le dernier bit 1 peut gagner beacoup de temps
