#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>
#include <sodium.h> // Assurez-vous d'avoir libsodium
#include "rsa.h"

int main() {
    // Définir une taille de buffer suffisamment grande pour les clés et les messages hexadécimaux
    // Une clé RSA de 2048 bits générera des nombres hexadécimaux d'environ 2048/4 = 512 caractères + '\0'
    // Pour être sûr, 4096 octets est une bonne marge
    const size_t BUFFER_SIZE = 4096;
    char n_hex[BUFFER_SIZE];
    char d_hex[BUFFER_SIZE];
    char e_hex[] = "10001"; // Exposant public standard en hex (65537)

    // 1. Génération des clés
    printf("Génération des clés RSA...\n");
    generate_rsa_keys(n_hex, d_hex, BUFFER_SIZE);
    printf("Clé publique N (hex) : %s\n", n_hex);
    printf("Clé privée D (hex)  : %s\n", d_hex);
    printf("\n");

    // 2. Test de chiffrement et déchiffrement
    // Le message doit être converti en hexadécimal avant le chiffrement
    // Pour simplifier, nous utilisons un exemple numérique direct converti en hex
    // En production, vous hacheriez/formateriez votre texte avant de le convertir en un grand entier/hex
    char original_message_hex[] = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"; // Exemple de message hex
    char encrypted_message_hex[BUFFER_SIZE];
    char decrypted_message_hex[BUFFER_SIZE];

    printf("Message original (hex) : %s\n", original_message_hex);

    rsa_encrypt_string(original_message_hex, e_hex, n_hex, encrypted_message_hex, BUFFER_SIZE);
    printf("Message chiffré (hex)  : %s\n", encrypted_message_hex);

    rsa_decrypt_string(encrypted_message_hex, d_hex, n_hex, decrypted_message_hex, BUFFER_SIZE);
    printf("Message déchiffré (hex): %s\n", decrypted_message_hex);

    if (strcmp(original_message_hex, decrypted_message_hex) == 0) {
        printf("Chiffrement/Déchiffrement réussi !\n\n");
    } else {
        printf("ERREUR: Chiffrement/Déchiffrement échoué.\n\n");
    }

    // 3. Test de signature et vérification
    char message_hash_hex[] = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"; // Exemple de hachage hex
    char signature_hex[BUFFER_SIZE];

    printf("Hachage du message à signer (hex) : %s\n", message_hash_hex);

    rsa_sign_string(message_hash_hex, d_hex, n_hex, signature_hex, BUFFER_SIZE);
    printf("Signature générée (hex)          : %s\n", signature_hex);

    // Vérification de la signature
    int is_valid = rsa_verify_string(message_hash_hex, signature_hex, e_hex, n_hex);
    if (is_valid) {
        printf("Vérification de la signature : SUCCÈS (La signature est valide)\n\n");
    } else {
        printf("Vérification de la signature : ÉCHEC (La signature n'est PAS valide)\n\n");
    }

    // Test avec un hachage modifié pour voir l'échec
    printf("Test de vérification avec hachage modifié (devrait échouer) :\n");
    char tampered_hash_hex[] = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543211"; // Hachage légèrement modifié
    is_valid = rsa_verify_string(tampered_hash_hex, signature_hex, e_hex, n_hex);
    if (is_valid) {
        printf("Vérification de la signature modifiée : SUCCÈS (ERREUR, devrait échouer)\n\n");
    } else {
        printf("Vérification de la signature modifiée : ÉCHEC (Attendu, la signature est invalide)\n\n");
    }

    return 0;
}