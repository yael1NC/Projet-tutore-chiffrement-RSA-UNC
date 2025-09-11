import socket
import json
import ctypes
import os
import hashlib

KEY_DIR = "keys"
PUB_N_FILE = os.path.join(KEY_DIR, "public_n.key")
PUB_E_FILE = os.path.join(KEY_DIR, "public_e.key")
BUFFER_SIZE = 8192

# --- Code modifié ---
try:
    lib_path = os.path.join(os.path.dirname(__file__), '..', 'rsa_lib.so')
    rsa_lib = ctypes.CDLL(os.path.abspath(lib_path))
except OSError as e:
    print(f"Erreur : Impossible de charger la bibliothèque C rsa_lib.so. Détails : {e}")
    exit(1)
# --- Fin du code modifié ---

# Fixed function signature to include algo_choice parameter
rsa_lib.rsa_encrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
rsa_lib.rsa_encrypt_string.restype = None


def rsa_encrypt_python(message, e_hex, n_hex, algo_choice=6):
    """
    Chiffre un message texte (pas hexadécimal) avec RSA
    """
    encrypt_message_hex_out = ctypes.create_string_buffer(BUFFER_SIZE)
    rsa_lib.rsa_encrypt_string(
        message.encode('utf-8'),  # Le message en bytes, pas en hex
        e_hex.encode('utf-8'), 
        n_hex.encode('utf-8'), 
        encrypt_message_hex_out, 
        BUFFER_SIZE, 
        algo_choice
    )
    return encrypt_message_hex_out.value.decode('utf-8')

# REMPLACEZ '127.0.0.1' par l'adresse IP du PC serveur !
SERVER_HOST = '127.0.0.1' 
SERVER_PORT = 65432

def load_public_keys():
    print("Chargement des clés publiques du serveur...")
    if (os.path.exists(PUB_N_FILE) and
        os.path.exists(PUB_E_FILE)):
        with open(PUB_N_FILE, 'r') as f:
            n_val = f.read().strip()
        with open(PUB_E_FILE, 'r') as f:
            e_val = f.read().strip()
        print("Clés publiques chargées avec succès.")
        return n_val, e_val
    else:
        print("Erreur : Clés publiques du serveur introuvables.")
        exit(1)

def run_client():
    n_val, e_val = load_public_keys()
    
    # Utilisez un message plus court pour éviter les problèmes de taille
    original_message = "Hello RSA!"
    print(f"\nMessage original : '{original_message}'")
    
    try:
        # Chiffrement du message (pas besoin de conversion hex ici)
        encrypted_msg_hex = rsa_encrypt_python(original_message, e_val, n_val)
        print(f"Message chiffré (hex) : {encrypted_msg_hex[:50]}...")
        
        request_data = {
            'operation': 'decrypt',
            'data': encrypted_msg_hex
        }

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            print(f"Connecté au serveur à {SERVER_HOST}:{SERVER_PORT}")
            s.sendall(json.dumps(request_data).encode('utf-8'))
            response_data = s.recv(4096)
            response = json.loads(response_data.decode('utf-8'))
            
            if response['status'] == 'success':
                decrypted_message = response['result']
                print(f"Message déchiffré par le serveur : '{decrypted_message}'")
                
                if original_message == decrypted_message:
                    print("✅ Test de chiffrement/déchiffrement réussi !")
                else:
                    print("❌ Erreur : Le message déchiffré ne correspond pas à l'original")
            else:
                print(f"Erreur du serveur : {response.get('message', 'Erreur inconnue')}")
                
    except Exception as e:
        print(f"Erreur lors du chiffrement : {e}")
        return
        
    except ConnectionRefusedError:
        print(f"Erreur : Impossible de se connecter au serveur à {SERVER_HOST}:{SERVER_PORT}. Assurez-vous que le serveur est en cours d'exécution.")
    except Exception as e:
        print(f"Une erreur est survenue : {e}")

if __name__ == "__main__":
    run_client()