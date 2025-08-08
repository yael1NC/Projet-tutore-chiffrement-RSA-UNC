import ctypes
import os

# Configuration des chemins de fichiers pour les clés
KEY_DIR = "keys"
PUB_N_FILE = os.path.join(KEY_DIR, "public_n.key")
PUB_E_FILE = os.path.join(KEY_DIR, "public_e.key")
PRIV_D_FILE = os.path.join(KEY_DIR, "private_d.key") # Seul d est privé, n est public

# Charger la bibliothèque C
try:
    # Assurez-vous que le fichier rsa_lib.so est dans le même répertoire
    # ou dans un chemin accessible par le système.
    rsa_lib = ctypes.CDLL('./rsa_lib.so')
except OSError as e:
    print(f"Erreur : Impossible de charger la bibliothèque C rsa_lib.so. Assurez-vous qu'elle est compilée et dans le bon chemin.")
    print(f"Détails de l'erreur : {e}")
    exit(1)

# Définir les signatures des fonctions C (nouvelle API basée sur les chaînes)

# void generate_rsa_keys(char* n_hex_out, char* d_hex_out, size_t buffer_size);
rsa_lib.generate_rsa_keys.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
rsa_lib.generate_rsa_keys.restype = None

# void rsa_encrypt_string(const char* non_encrypt_hex, const char* e_hex, const char* n_hex, char* encrypt_message_hex_out, size_t buffer_size);
rsa_lib.rsa_encrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
rsa_lib.rsa_encrypt_string.restype = None

# void rsa_decrypt_string(const char* encrypt_message_hex, const char* d_hex, const char* n_hex, char* non_encrypt_hex_out, size_t buffer_size);
rsa_lib.rsa_decrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
rsa_lib.rsa_decrypt_string.restype = None

# void rsa_sign_string(const char* message_hash_hex, const char* d_hex, const char* n_hex, char* signature_hex_out, size_t buffer_size);
rsa_lib.rsa_sign_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
rsa_lib.rsa_sign_string.restype = None

# int rsa_verify_string(const char* message_hash_hex, const char* signature_hex, const char* e_hex, const char* n_hex);
rsa_lib.rsa_verify_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
rsa_lib.rsa_verify_string.restype = ctypes.c_int

# Fonctions Python pour la persistance des clés (lecture/écriture de fichiers)

def save_key_component(filename, value_str):
    """Sauvegarde un composant de clé (une chaîne hex) dans un fichier."""
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w') as f:
        f.write(value_str)

def load_key_component(filename):
    """Charge un composant de clé (une chaîne hex) depuis un fichier."""
    try:
        with open(filename, 'r') as f:
            return f.read().strip() # Supprime les espaces blancs
    except FileNotFoundError:
        return None

def save_python_keys(n_hex, e_hex, d_hex):
    """Sauvegarde les clés RSA (chaînes hex) dans des fichiers."""
    save_key_component(PUB_N_FILE, n_hex)
    save_key_component(PUB_E_FILE, e_hex)
    save_key_component(PRIV_D_FILE, d_hex)
    # Note: La modification des permissions du fichier n'est pas gérée ici par os.chmod
    # pour la démo, mais devrait l'être en production pour PRIV_D_FILE (0o600)
    print("Clés sauvegardées avec succès.")

def load_python_keys():
    """Charge les clés RSA (chaînes hex) depuis les fichiers."""
    n_pub = load_key_component(PUB_N_FILE)
    e_pub = load_key_component(PUB_E_FILE)
    d_priv = load_key_component(PRIV_D_FILE)

    if all([n_pub, e_pub, d_priv]):
        print("Clés chargées avec succès.")
        return {'n': n_pub, 'e': e_pub, 'd': d_priv}
    else:
        print("Aucune clé trouvée, ou fichiers incomplets.")
        return None

# Fonctions wrapper Python pour les opérations RSA

# Taille de buffer recommandée pour les sorties hexadécimales des fonctions C
# Une clé RSA de 2048 bits = 2048/8 = 256 octets. En hex, 2 caractères par octet = 512 caractères.
# Ajouter une marge pour être sûr, par exemple 1024 ou 2048.
BUFFER_SIZE_C = 2048 # En octets, pour les buffers C

def generate_rsa_keys_python():
    """Génère des clés RSA en utilisant la bibliothèque C et les retourne en Python (chaînes hex)."""
    n_buffer = ctypes.create_string_buffer(BUFFER_SIZE_C)
    d_buffer = ctypes.create_string_buffer(BUFFER_SIZE_C)

    rsa_lib.generate_rsa_keys(n_buffer, d_buffer, BUFFER_SIZE_C)

    n_hex = n_buffer.value.decode('utf-8')
    d_hex = d_buffer.value.decode('utf-8')
    e_hex = "10001" # Exposant public fixe

    print(f"Clé publique générée (N, E) : ({n_hex[:50]}..., {e_hex})") # Affiche les 50 premiers chars pour la lisibilité
    print(f"Clé privée générée (D) : ({d_hex[:50]}...)")

    return n_hex, e_hex, d_hex

def rsa_encrypt_python(message_hex, e_hex, n_hex):
    """Chiffre un message (chaîne hex) en utilisant la clé publique (chaînes hex)."""
    encrypted_buffer = ctypes.create_string_buffer(BUFFER_SIZE_C)
    rsa_lib.rsa_encrypt_string(
        message_hex.encode('utf-8'),
        e_hex.encode('utf-8'),
        n_hex.encode('utf-8'),
        encrypted_buffer,
        BUFFER_SIZE_C
    )
    return encrypted_buffer.value.decode('utf-8')

def rsa_decrypt_python(ciphertext_hex, d_hex, n_hex):
    """Déchiffre un message (chaîne hex) en utilisant la clé privée (chaînes hex)."""
    decrypted_buffer = ctypes.create_string_buffer(BUFFER_SIZE_C)
    rsa_lib.rsa_decrypt_string(
        ciphertext_hex.encode('utf-8'),
        d_hex.encode('utf-8'),
        n_hex.encode('utf-8'),
        decrypted_buffer,
        BUFFER_SIZE_C
    )
    return decrypted_buffer.value.decode('utf-8')

def rsa_sign_python(message_hash_hex, d_hex, n_hex):
    """Signe un hachage de message (chaîne hex) en utilisant la clé privée (chaînes hex)."""
    signature_buffer = ctypes.create_string_buffer(BUFFER_SIZE_C)
    rsa_lib.rsa_sign_string(
        message_hash_hex.encode('utf-8'),
        d_hex.encode('utf-8'),
        n_hex.encode('utf-8'),
        signature_buffer,
        BUFFER_SIZE_C
    )
    return signature_buffer.value.decode('utf-8')

def rsa_verify_python(message_hash_hex, signature_hex, e_hex, n_hex):
    """Vérifie une signature (chaîne hex) en utilisant la clé publique (chaînes hex)."""
    is_valid = rsa_lib.rsa_verify_string(
        message_hash_hex.encode('utf-8'),
        signature_hex.encode('utf-8'),
        e_hex.encode('utf-8'),
        n_hex.encode('utf-8')
    )
    return bool(is_valid) # Convertit le 0/1 C en True/False Python


# Logique principale du serveur Python
if __name__ == "__main__":
    # Assurez-vous que le répertoire des clés existe
    os.makedirs(KEY_DIR, exist_ok=True)

    # Tente de charger les clés existantes
    keys_data = load_python_keys()

    if not keys_data:
        print("Génération de nouvelles clés...")
        n, e, d = generate_rsa_keys_python()
        save_python_keys(n, e, d)
        keys_data = {'n': n, 'e': e, 'd': d}

    n_val = keys_data['n']
    e_val = keys_data['e']
    d_val = keys_data['d']

    print(f"\nClés actives (N, E, D) : (N:{n_val[:50]}..., E:{e_val}, D:{d_val[:50]}...)")


    # Test des opérations RSA avec les clés gérées par Python
    print("\nTest de chiffrement/déchiffrement")
    # Pour un test simple, un nombre peut être représenté par son hexadécimal
    # En pratique, le message serait haché ou converti en un grand entier puis en hex
    original_msg_hex = "abcdef1234567890abcdef1234567890" # Exemple de message hex
    print(f"Message original (hex): {original_msg_hex}")

    encrypted_msg_hex = rsa_encrypt_python(original_msg_hex, e_val, n_val)
    print(f"Message chiffré (hex): {encrypted_msg_hex[:50]}...")

    decrypted_msg_hex = rsa_decrypt_python(encrypted_msg_hex, d_val, n_val)
    print(f"Message déchiffré (hex): {decrypted_msg_hex}")

    if original_msg_hex == decrypted_msg_hex:
        print("Chiffrement/Déchiffrement réussi avec Python et C !")
    else:
        print("ERREUR: Chiffrement/Déchiffrement échoué.")

    print("\nTest de signature/vérification")
    message_hash_hex = "fedcba9876543210fedcba9876543210" # Exemple de hachage hex
    print(f"Hachage du message (hex): {message_hash_hex}")

    signature_hex = rsa_sign_python(message_hash_hex, d_val, n_val)
    print(f"Signature (hex): {signature_hex[:50]}...")

    is_valid_signature = rsa_verify_python(message_hash_hex, signature_hex, e_val, n_val)
    print(f"Vérification de la signature : {is_valid_signature}")
    if is_valid_signature:
        print("Signature valide !")
    else:
        print("Signature invalide !")

    # Test avec un hachage modifié pour voir l'échec
    print("\nTest de vérification avec hachage modifié (devrait échouer)")
    tampered_hash_hex = "fedcba9876543210fedcba9876543211" # Légèrement modifié
    is_valid_tampered = rsa_verify_python(tampered_hash_hex, signature_hex, e_val, n_val)
    print(f"Vérification de la signature avec hachage altéré : {is_valid_tampered}")
    if not is_valid_tampered:
        print("Échec de vérification attendu pour le hachage altéré.")
    else:
        print("ERREUR : La vérification a réussi pour un hachage altéré.")