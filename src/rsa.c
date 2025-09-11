#include "rsa.h"
    
// Generate a random number of 4096 bits
void generate_random_nbr(mpz_t result) {
    char buf[512]; // creation d'un buffer avec 512 octets, donc 4096 bits
    randombytes_buf(buf, (512)); 

    mpz_import(result, 512, 1, 1, 1, 0, buf); 

    sodium_memzero(buf, 512);
}

// Return 0 if n is probably prime, 1 if n is not prime
int is_prime(mpz_t n) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL));

    if(mpz_tstbit(n, 0) == 0) return 0;
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

// Return 0 if n is probably prime, 1 if n is not prime
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

// Generate a prime number of 4096 bits
void generate_prime_nbr(mpz_t prime) {
    generate_random_nbr(prime);

    while(!(is_prime(prime))) {
        generate_random_nbr(prime);
    }
}

// Generate RSA keys (n, d) and return them as hex strings
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

// RSA encryption with choice of exponentiation algorithm
void rsa_encrypt_string(const char* non_encrypt, const char* e_hex, const char* n_hex, char* encrypt_message_hex, size_t buffer_size, int algo_choice) {
    mpz_t m, c, e, n;

    mpz_inits(m, c, e, n, NULL);

    mpz_set_str(e, e_hex, 16);
    mpz_set_str(n, n_hex, 16);

    
    mpz_import(m, strlen(non_encrypt), 1, 1, 0, 0, non_encrypt);

    // Chiffrement : c = m^e mod n
    switch(algo_choice) {
        case 1:
            square_and_multiply(c, m, e, n);
            break;
        case 2:
            square_and_multiply_always(c, m, e, n);
            break;
        case 3:
            montgomery_ladder(c, m, e, n);
            break;
        case 4:
            semi_interleaved_ladder(c, m, e, n);
            break;
        case 5:
            fully_interleaved_ladder(c, m, e, n);
            break;
        case 6:
            mpz_powm(c, m, e, n);
            break;
    }

    char* hex = mpz_get_str(NULL, 16, c);
    strncpy(encrypt_message_hex, hex, buffer_size - 1);
    encrypt_message_hex[buffer_size - 1] = '\0';

    free(hex);
    mpz_clears(m, c, e, n, NULL);
}

// RSA decryption with choice of exponentiation algorithm
void rsa_decrypt_string(const char* encrypt_message_hex, const char* d_hex, const char* n_hex, char* non_encrypt, size_t buffer_size, int algo_choice) {
    mpz_t c, m, d, n;
    mpz_inits(c, m, d, n, NULL);

    mpz_set_str(c, encrypt_message_hex, 16);
    mpz_set_str(d, d_hex, 16);
    mpz_set_str(n, n_hex, 16);

    // Dechiffrement : m = c^d mod n
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
        case 6:
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

// Algorithm 1 Square and multiply for the modular exponentiation
void square_and_multiply(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n) {
    mpz_t x, temp;
    mpz_inits(x, temp, NULL);

    mpz_set_ui(x, 1);

    size_t bit_length = mpz_sizeinbase(k, 2);

    for (size_t i = bit_length; i > 0; i--) {
        size_t bit_index = i - 1; 
        
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

// Algorithm 2 Square and multiply always for the modular exponentiation
void square_and_multiply_always(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n) {
    mpz_t x, y, temp;
    mpz_inits(x, y, temp, NULL);

    mpz_set_ui(x, 1);

    size_t bit_length = mpz_sizeinbase(k, 2);

    for (size_t i = bit_length; i > 0; i--) {
        size_t bit_index = i - 1;
        
        mpz_mul(temp, x, x);
        mpz_mod(x, temp, n);

        mpz_mul(temp, x, a);
        mpz_mod(temp, temp, n);

        if (mpz_tstbit(k, bit_index)) {
            mpz_set(x, temp); 
        } else {
            mpz_set(y, temp); 
        }
    }

    mpz_set(result, x);
    mpz_clears(x, y, temp, NULL);
}

// Algorithm 3 Montgomery ladder for the modular exponentiation
void montgomery_ladder(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n) {
    mpz_t x, y, temp;
    mpz_inits(x, y, temp, NULL);

    // 1: x = 1
    mpz_set_ui(x, 1);
    
    // 2: y = a mod n
    mpz_mod(y, a, n);

    // 3: pour i = d à 0
    size_t bit_length = mpz_sizeinbase(k, 2);
    
    for (size_t i = bit_length; i > 0; i--) {
        size_t bit_index = i - 1;  // bit_index va de (bit_length-1) à 0
        
        if (mpz_tstbit(k, bit_index)) { // si k[i] = 1
            
            mpz_mul(temp, x, y);     // x = xy mod n
            mpz_mod(x, temp, n);

            mpz_mul(temp, y, y);     // y = y*y mod n
            mpz_mod(y, temp, n);
        } else {
            mpz_mul(temp, x, y);     // y = xy mod n
            mpz_mod(y, temp, n);

            mpz_mul(temp, x, x);     // x = x*x mod n
            mpz_mod(x, temp, n);
        }
    }

    mpz_set(result, x);
    mpz_clears(x, y, temp, NULL);
}


// Algorithm 13 Semi-interleaved ladder for the modular exponentiation
void semi_interleaved_ladder(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n) {
    mpz_t x, y, z, m, c1, c2, temp1, temp2;
    mpz_inits(x, y, z, m, c1, c2, temp1, temp2, NULL);

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL));

    // 1: x = 1
    mpz_set_ui(x, 1);
    
    // 2: y = a mod n
    mpz_mod(y, a, n);

    // 3: m = random([0, n−1])
    mpz_urandomm(m, state, n);

    // 4: c1 = ma mod n
    mpz_mul(c1, m, a);
    mpz_mod(c1, c1, n);

    // 5: c2 = 1 − (c1a + m) mod n
    mpz_mul(temp1, c1, a);     // c1 * a
    mpz_add(temp1, temp1, m);  // c1 * a + m
    mpz_set_ui(temp2, 1);      // temp2 = 1
    mpz_sub(temp2, temp2, temp1); // 1 - (c1*a + m)
    mpz_mod(c2, temp2, n);     // c2 = 1 - (c1*a + m) mod n

    size_t bit_length = mpz_sizeinbase(k, 2);
    size_t d = bit_length - 1;

    // 6: for i = d to 0 do
    for (size_t i = d; i != SIZE_MAX; i--) { 
        
        // 7: if k[i] = 1 then
        if (mpz_tstbit(k, i)) {
            // 8: z = y*y mod n
            mpz_mul(z, y, y);
            mpz_mod(z, z, n);

            // 9: x = c1(x*x + z) + c2*x*y mod n
            mpz_mul(temp1, x, x);          // x*x
            mpz_add(temp1, temp1, z);      // x*x + z
            mpz_mul(temp1, temp1, c1);     // c1(x*x + z)

            mpz_mul(temp2, c2, x);         // c2 * x
            mpz_mul(temp2, temp2, y);      // c2 * x * y

            mpz_add(temp1, temp1, temp2);  // c1(x*x + z) + c2*x*y
            mpz_mod(x, temp1, n);
            
            // 10: y = z
            mpz_set(y, z);
            
        } else {
            // 11: else
            // 12: z = x*x mod n
            mpz_mul(z, x, x);
            mpz_mod(z, z, n);

            // 13: y = c1(y*y + z) + c2*y*x mod n 
            mpz_mul(temp1, y, y);          // y*y
            mpz_add(temp1, temp1, z);      // y*y + z
            mpz_mul(temp1, temp1, c1);     // c1(y*y + z)

            mpz_mul(temp2, c2, y);         // c2 * y
            mpz_mul(temp2, temp2, x);      // c2 * y * x

            mpz_add(temp1, temp1, temp2);  // c1(y*y + z) + c2*y*x
            mpz_mod(y, temp1, n);
            
            // 14: x = z
            mpz_set(x, z);
        }
        // 15: end if
    }
    // 16: end for

    // 17: return x
    mpz_set(result, x);

    mpz_clears(x, y, z, m, c1, c2, temp1, temp2, NULL);
    gmp_randclear(state);
}


// Extended Euclidean Algorithm to find gcd and coefficients
void extended_euclidean(mpz_t gcd, mpz_t u, const mpz_t a, const mpz_t n) {
    mpz_t r0, r1, u0, u1, v0, v1, temp, q;
    mpz_inits(r0, r1, u0, u1, v0, v1, temp, q, NULL);
    
    mpz_set(r0, n);    // r0 = n
    mpz_set(r1, a);    // r1 = a
    mpz_set_ui(u0, 0); // u0 = 0
    mpz_set_ui(u1, 1); // u1 = 1
    mpz_set_ui(v0, 1); // v0 = 1
    mpz_set_ui(v1, 0); // v1 = 0
    
    while (mpz_cmp_ui(r1, 0) != 0) {
        // q = r0 / r1
        mpz_fdiv_q(q, r0, r1);
        
        // r0, r1 = r1, r0 - q*r1
        mpz_mul(temp, q, r1);
        mpz_sub(temp, r0, temp);
        mpz_set(r0, r1);
        mpz_set(r1, temp);
        
        // u0, u1 = u1, u0 - q*u1
        mpz_mul(temp, q, u1);
        mpz_sub(temp, u0, temp);
        mpz_set(u0, u1);
        mpz_set(u1, temp);
        
        // v0, v1 = v1, v0 - q*v1
        mpz_mul(temp, q, v1);
        mpz_sub(temp, v0, temp);
        mpz_set(v0, v1);
        mpz_set(v1, temp);
    }
    
    mpz_set(gcd, r0);  // gcd
    mpz_set(u, u0);    // coefficient u
    
    mpz_clears(r0, r1, u0, u1, v0, v1, temp, q, NULL);
}

// Algorithm 14 Fully-interleaved ladder for the modular exponentiation
void fully_interleaved_ladder(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n) {
    mpz_t l, v0, v2, v3, d1, d2, d3, u1, u2, u3;
    mpz_t c0, c1, c2, c3, x, y, z;
    mpz_t temp1, temp2, temp3, n_minus_2;
    mpz_inits(l, v0, v2, v3, d1, d2, d3, u1, u2, u3, NULL);
    mpz_inits(c0, c1, c2, c3, x, y, z, NULL);
    mpz_inits(temp1, temp2, temp3, n_minus_2, NULL);
    
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL));
    
    mpz_sub_ui(n_minus_2, n, 2);  // n - 2
    
    // 1: do
    do {
        // 2: l = random([2, n − 2] \ {a})
        do {
            mpz_urandomm(temp1, state, n_minus_2);  // [0, n-3]
            mpz_add_ui(l, temp1, 2);                // [2, n-1]
        } while (mpz_cmp(l, a) == 0);  // Exclure a
        
        // 3: v0 = l − a mod n
        mpz_sub(v0, l, a);
        mpz_mod(v0, v0, n);
        
        // 4: (d1, u1) = EEA(l, n)
        extended_euclidean(d1, u1, l, n);
        
        // 5: v2 = l*l − 1 mod n
        mpz_mul(v2, l, l);
        mpz_sub_ui(v2, v2, 1);
        mpz_mod(v2, v2, n);
        
        // 6: (d2, u2) = EEA(v2, n)
        extended_euclidean(d2, u2, v2, n);
        
        // 7: v3 = l^3 − a mod n
        mpz_mul(temp1, l, l);
        mpz_mul(v3, temp1, l);  //l^3
        mpz_sub(v3, v3, a);
        mpz_mod(v3, v3, n);
        
        // 8: (d3, u3) = EEA(v3, n)
        extended_euclidean(d3, u3, v3, n);
        
    // 9: while v0 mod n = 0 ∨ d1 != 1 ∨ d2 != 1 ∨ d3 != 1
    } while (mpz_cmp_ui(v0, 0) == 0 ||  mpz_cmp_ui(d1, 1) != 0 || mpz_cmp_ui(d2, 1) != 0 || mpz_cmp_ui(d3, 1) != 0);
    
    // 10: c0 = u1*u2*v3 mod n
    mpz_mul(temp1, u1, u2);
    mpz_mul(c0, temp1, v3);
    mpz_mod(c0, c0, n);
    
    // 11: c1 = −v0*u2 mod n
    mpz_mul(temp1, v0, u2);
    mpz_neg(c1, temp1);
    mpz_mod(c1, c1, n);
    
    // 12: c2 = a*v2*u3 mod n
    mpz_mul(temp1, a, v2);
    mpz_mul(c2, temp1, u3);
    mpz_mod(c2, c2, n);
    
    // 13: c3 = l*v0*u3 mod n
    mpz_mul(temp1, l, v0);
    mpz_mul(c3, temp1, u3);
    mpz_mod(c3, c3, n);
    
    // 14: x = 1
    mpz_set_ui(x, 1);
    
    // 15: y = l
    mpz_set(y, l);
    
    size_t bit_length = mpz_sizeinbase(k, 2);
    size_t d = bit_length - 1;
    
    // 16: for i = d to 0 do
    for (size_t i = d; i != SIZE_MAX; i--) {
        
        // 17: if k[i] = 1 then
        if (mpz_tstbit(k, i)) {
            // 18: z = y*y mod n
            mpz_mul(z, y, y);
            mpz_mod(z, z, n);
            
            // 19: x = c0*xy + c1*z mod n
            mpz_mul(temp1, c0, x);
            mpz_mul(temp1, temp1, y);  // c0*xy
            mpz_mul(temp2, c1, z);     // c1*z
            mpz_add(temp1, temp1, temp2);
            mpz_mod(x, temp1, n);

            // 20: y = c2*z + c3*x mod n
            mpz_mul(temp1, c2, z);     // c2*z
            mpz_mul(temp2, c3, x);     // c3*x
            mpz_add(temp1, temp1, temp2);
            mpz_mod(y, temp1, n);
            
        } else {
            // 21: else
            // 22: z = x*x mod n
            mpz_mul(z, x, x);
            mpz_mod(z, z, n);

            // 23: y = c0*y*x + c1*z mod n
            mpz_mul(temp1, c0, y);
            mpz_mul(temp1, temp1, x);  // c0*y*x
            mpz_mul(temp2, c1, z);     // c1*z
            mpz_add(temp1, temp1, temp2);
            mpz_mod(y, temp1, n);
            
            // 24: x = c2*z + c3*y mod n
            mpz_mul(temp1, c2, z);     // c2*z
            mpz_mul(temp2, c3, y);     // c3*y
            mpz_add(temp1, temp1, temp2);
            mpz_mod(x, temp1, n);
        }
        // 25: end if
    }
    // 26: end for
    
    // 27: return x
    mpz_set(result, x);
    
    mpz_clears(l, v0, v2, v3, d1, d2, d3, u1, u2, u3, NULL);
    mpz_clears(c0, c1, c2, c3, x, y, z, NULL);
    mpz_clears(temp1, temp2, temp3, n_minus_2, NULL);
    gmp_randclear(state);
}