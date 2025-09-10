# Implémentation Sécurisée du Schéma de Chiffrement RSA

Une implémentation complète du chiffrement RSA en C.

## 🔐 Fonctionnalités

- **Génération de clés RSA 4096 bits** avec nombres premiers cryptographiquement sécurisés
- **Test de primalité Miller-Rabin** avec 25 itérations pour une sécurité renforcée
- **6 algorithmes d'exponentiation modulaire** différents pour l'analyse comparative


## 🧮 Algorithmes d'Exponentiation Modulaire Implémentés

#### 1. Square and Multiply (Classique)
```c
void square_and_multiply(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n)
```

#### 2. Square and Multiply Always
```c
void square_and_multiply_always(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n)
```

#### 3. Montgomery Ladder
```c
void montgomery_ladder(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n)
```

#### 4. Semi-Interleaved Ladder
```c
void semi_interleaved_ladder(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n)
```

#### 5. Fully-Interleaved Ladder
```c
void fully_interleaved_ladder(mpz_t result, const mpz_t a, const mpz_t k, const mpz_t n)
```

## 🛠️ Compilation et Dépendances

### Prérequis
```bash
# Ubuntu/Debian
sudo apt install libgmp-dev libsodium-dev make gcc

# CentOS/RHEL/Fedora
sudo dnf install gmp-devel libsodium-devel make gcc

# macOS
brew install gmp libsodium
```

### Compilation
```bash
make          # Compile la bibliothèque rsa_lib.so
make clean    # Nettoie les fichiers générés
make rebuild  # Clean + compile
```

## 🚀 Utilisation

### Génération Automatique de Clés RSA
```c
#include "rsa.h"

char n_hex[4096], d_hex[4096];
generate_rsa_keys(n_hex, d_hex, sizeof(n_hex));

printf("Clé publique (n): %s\n", n_hex);
printf("Clé privée (d): %s\n", d_hex);
```

### Chiffrement avec Choix d'Algorithme
```c
const char* message = "Hello World!";
const char* e_hex = "10001";  // 65537 en hexadécimal
char encrypted[4096];

rsa_encrypt_string(message, e_hex, n_hex, encrypted, sizeof(encrypted), 3);
//                                                                      ^ Choisir l'algorithme
```

### Déchiffrement
```c
char decrypted[256];

// Utilisation du même algorithme pour le déchiffrement
rsa_decrypt_string(encrypted, d_hex, n_hex, decrypted, sizeof(decrypted), 3);
//                                                                        ^ Choisir l'algorithme

printf("Message déchiffré: %s\n", decrypted);
```

### Exemple Complet
```c
#include "rsa.h"
#include <stdio.h>

int main() {
    // Génération des clés
    char n_hex[4096], d_hex[4096];
    generate_rsa_keys(n_hex, d_hex, sizeof(n_hex));
    
    // Message à chiffrer
    const char* message = "Message secret!";
    const char* e_hex = "10001";
    
    // Chiffrement avec Fully-Interleaved Ladder
    char encrypted[4096];
    rsa_encrypt_string(message, e_hex, n_hex, encrypted, sizeof(encrypted), 5);
//                                                                          ^ Choisir l'algorithme
    
    // Déchiffrement
    char decrypted[256];
    rsa_decrypt_string(encrypted, d_hex, n_hex, decrypted, sizeof(decrypted), 5);
//                                                                            ^ Choisir l'algorithme

    printf("Original:  %s\n", message);
    printf("Chiffré:   %s\n", encrypted);
    printf("Déchiffré: %s\n", decrypted);
    
    return 0;
}
```

## 🔒 Sécurité

### Paramètres de Sécurité
- **Taille des clés**: 4096 bits 
- **Exposant public**: 65537 
- **Test de primalité**: Miller-Rabin avec 25 itérations 
- **Générateur aléatoire**: libsodium

