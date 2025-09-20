# Implémentation Sécurisée du Schéma de Chiffrement RSA

## 🔐 Fonctionnalités

- **Génération de clés RSA 4096 bits** avec nombres premiers cryptographiquement sécurisés
- **Test de primalité Miller-Rabin** avec 25 itérations pour une sécurité renforcée
- **6 algorithmes d'exponentiation modulaire** différents pour l'analyse comparative
- **Interface Python interactive** avec choix d'algorithmes
- **Système client-serveur** avec protection des clés par chiffrement
- **Gestionnaire de clés sécurisé** avec AES-256-GCM

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

## 🧮 Algorithmes RSA Chiffrement/Déchiffrement
### 1. Chiffrement

```c
void rsa_encrypt_string(const char* non_encrypt, const char* e_hex, const char* n_hex, char* encrypt_message_hex, size_t buffer_size, int algo_choice);
```

**Description :** Chiffre une chaîne de caractères en utilisant le chiffrement RSA avec clé publique.

**Paramètres :**
- `non_encrypt` : Le message original à chiffrer
- `e_hex` : Exposant public en format hexadécimal
- `n_hex` : Module en format hexadécimal
- `encrypt_message_hex` : Buffer de sortie pour le message chiffré (hexadécimal)
- `buffer_size` : Taille du buffer de sortie
- `algo_choice` : Sélection de la variante d'algorithme

### 2. Déchiffrement

```c
void rsa_decrypt_string(const char* encrypt_message_hex, const char* d_hex, const char* n_hex, char* non_encrypt, size_t buffer_size, int algo_choice);
```

**Paramètres :**
- `encrypt_message_hex` : Le message chiffré en format hexadécimal
- `d_hex` : Exposant privé en format hexadécimal
- `n_hex` : Module en format hexadécimal
- `non_encrypt` : Buffer de sortie pour le message déchiffré
- `buffer_size` : Taille du buffer de sortie
- `algo_choice` : Sélection de la variante d'algorithme

## 🛠️ Compilation et Dépendances

### Prérequis
```bash
# Ubuntu/Debian
sudo apt install libgmp-dev libsodium-dev make gcc python3 python3-pip

# CentOS/RHEL/Fedora
sudo dnf install gmp-devel libsodium-devel make gcc python3 python3-pip

# macOS
brew install gmp libsodium python3
```

### Dépendances Python
```bash
pip install cryptography
```

### Compilation
```bash
make          # Compile la bibliothèque rsa_lib.so
make clean    # Nettoie les fichiers générés
make rebuild  # Clean + compile
```

## 🚀 Utilisation en C

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

    if (sodium_init() < 0) {
        printf("Impossible d'initialiser libsodium\n");
        return 1;
    }

    // Génération des clés
    char n_hex[4096], d_hex[4096];
    generate_rsa_keys(n_hex, d_hex, sizeof(n_hex));
    
    // Message à chiffrer
    const char* message = "Message secret!";
    const char* e_hex = "10001";
    
    // Chiffrement avec Fully-Interleaved Ladder pour exemple
    char encrypted[4096];
    rsa_encrypt_string(message, e_hex, n_hex, encrypted, sizeof(encrypted), 5);
//                                                                          ^ Choisir l'algorithme
    
    // Dechiffrement
    char decrypted[256];
    rsa_decrypt_string(encrypted, d_hex, n_hex, decrypted, sizeof(decrypted), 5);
//                                                                            ^ Choisir l'algorithme

    printf("Original:  %s\n", message);
    printf("Chiffre:   %s\n", encrypted);
    printf("Dechiffre: %s\n", decrypted);
    
    return 0;
}
```
```bash
gcc -Wall -Wextra -g -O0 main.c rsa.c -o test_rsa -lgmp -lsodium
```

## 🐍 Utilisation en Python

# Si il vous est demandé, Mot de Passe Sécurisé : 1234

### Installation Rapide
```bash
cd python/
python3 setup_secure_rsa.py
```

### Interface Interactive Principale
```bash
cd python/
python3 main.py
```

**Menu principal :**
- Chiffrer/déchiffrer des messages
- Comparer les performances des algorithmes
- Générer de nouvelles clés
- Tests complets avec vérification

### Système Client-Serveur

#### Démarrage du Serveur
```bash
cd python/
python3 rsa_server_secure.py
```

Le serveur :
- Génère automatiquement des clés sécurisées
- Protège les clés privées avec AES-256-GCM
- Accepte les connexions pour déchiffrement

#### Utilisation du Client
```bash
cd python/
python3 client_secure.py
```

Le client :
- Récupère automatiquement les clés publiques du serveur
- Chiffre les messages localement
- Envoie au serveur pour déchiffrement et vérification

#### Configuration Avancée
```bash
# Changer l'adresse du serveur
python3 client_secure.py

# Gestion des clés
python3 rsa_server_secure.py --manage-keys

# Migration des clés existantes
python3 migration_tool.py
```

### Benchmark des Algorithmes
```bash
cd python/
python3 main.py
# Choisir l'option 4 pour le benchmark automatique
```

### Tests Rapides
```bash
# Test simple de la bibliothèque C
cd python/
python3 -c "
import ctypes
lib = ctypes.CDLL('../rsa_lib.so')
print('Bibliothèque chargée avec succès!')
"

# Test client-serveur rapide
python3 client_secure.py "Test rapide"
```

### Structure du Projet
```
Projet-RSA/
├── src/
│   ├── rsa.h                    # Header C
│   └── rsa.c                    # Implémentation C
├── python/
│   ├── main.py                  # Interface principale
│   ├── rsa_server_secure.py     # Serveur avec clés sécurisées
│   ├── client_secure.py         # Client sécurisé
│   ├── key_manager.py           # Gestionnaire de clés
│   ├── migration_tool.py        # Outil de migration
│   └── setup_secure_rsa.py      # Installation automatique
├── rsa_lib.so                   # Bibliothèque compilée
├── Makefile                     # Build system
├── config.ini                   # Configuration
└── README.md                    # Documentation
```

### Algorithmes Disponibles (Python)
1. **Square and Multiply** - Basique, rapide
2. **Square and Multiply Always** - Résistant aux attaques par canal auxiliaire
3. **Montgomery Ladder** - Équilibré performance/sécurité
4. **Semi-interleaved Ladder** - Sécurisé contre les attaques temporelles
5. **Fully-interleaved Ladder** - Maximum de sécurité
6. **GMP mpz_powm** - Optimisé par défaut (recommandé)

### Sécurité des Clés Python
- **Chiffrement AES-256-GCM** des clés privées
- **Dérivation PBKDF2-HMAC-SHA256** (100,000 itérations)
- **Sel cryptographique** unique par installation
- **Effacement sécurisé** des clés temporaires
- **Permissions restrictives** sur les fichiers

### Exemples d'Usage Avancé

#### Benchmark de Performance
```python
# Dans l'interface Python
python3 main.py
# Choisir option 4, puis entrer un message de test
# Résultats automatiques pour tous les algorithmes
```

#### Test de Résistance aux Attaques
```python
# Test avec différentes tailles de messages
python3 main.py
# Option 3 pour tests complets avec vérification
```

#### Configuration Réseau
```python
# Modifier l'IP du serveur dans client_secure.py
SERVER_HOST = '192.168.1.100'  # IP du serveur distant
```

## 🔒 Sécurité

### Paramètres de Sécurité C
- **Taille des clés**: 4096 bits 
- **Exposant public**: 65537 
- **Test de primalité**: Miller-Rabin avec 25 itérations 
- **Générateur aléatoire**: libsodium

### Sécurité Python Additionnelle
- **Protection des clés**: AES-256-GCM + PBKDF2 (100k itérations)
- **Authentification**: Tag GCM pour intégrité
- **Gestion mémoire**: Effacement sécurisé des secrets
- **Permissions**: Accès restreint aux fichiers sensibles
