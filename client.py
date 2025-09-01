import socket
import json
import ctypes
import os
import hashlib

KEY_DIR = "keys"
PUB_N_FILE = os.path.join(KEY_DIR, "public_n.key")
PUB_E_FILE = os.path.join(KEY_DIR, "public_e.key")
BUFFER_SIZE = 8192

try:
    rsa_lib = ctypes.CDLL('./rsa_lib.so')
except OSError as e:
    print(f"Erreur : Impossible de charger la bibliothèque C rsa_lib.so. Détails : {e}")
    exit(1)

rsa_lib.rsa_encrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
rsa_lib.rsa_encrypt_string.restype = None


def rsa_encrypt_python(non_encrypt_hex, e_hex, n_hex):
    encrypt_message_hex_out = ctypes.create_string_buffer(BUFFER_SIZE)
    rsa_lib.rsa_encrypt_string(non_encrypt_hex.encode('utf-8'), e_hex.encode('utf-8'), n_hex.encode('utf-8'), encrypt_message_hex_out, BUFFER_SIZE)
    return encrypt_message_hex_out.value.decode('utf-8')

# REMPLACEZ '192.168.0.141' par l'adresse IP du PC serveur !
SERVER_HOST = '192.168.0.141' 
SERVER_PORT = 65432

def load_public_keys():
    """Charge les clés publiques du serveur depuis les fichiers."""
    print("Chargement des clés publiques du serveur...")
    if (os.path.exists(PUB_N_FILE) and
        os.path.exists(PUB_E_FILE)):
        with open(PUB_N_FILE, 'r') as f:
            n_val = f.read()
        with open(PUB_E_FILE, 'r') as f:
            e_val = f.read()
        print("Clés publiques chargées avec succès.")
        return n_val, e_val
    else:
        print("Erreur : Clés publiques du serveur introuvables. Assurez-vous d'avoir copié les fichiers 'public_n.key' et 'public_e.key' du PC serveur dans le dossier 'keys' ici.")
        exit(1)

def run_client():
    n_val, e_val = load_public_keys()
    
    original_message = "Bonjour Serveur, ceci est un message super secret !"
    print(f"\nMessage original : '{original_message}'")

    original_msg_hex = original_message.encode('utf-8').hex()
    print(f"Message converti en hex : {original_msg_hex}")

    encrypted_msg_hex = rsa_encrypt_python(original_msg_hex, e_val, n_val)
    print(f"Message chiffré (hex) : {encrypted_msg_hex[:50]}...")

    request_data = {
        'operation': 'decrypt',
        'data': encrypted_msg_hex
    }
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            print(f"Connecté au serveur à {SERVER_HOST}:{SERVER_PORT}")
            
            s.sendall(json.dumps(request_data).encode('utf-8'))
            
            response_data = s.recv(4096)
            response = json.loads(response_data.decode('utf-8'))
            
            if response['status'] == 'success':
                decrypted_msg_hex = response['result']
                decrypted_message = bytes.fromhex(decrypted_msg_hex).decode('utf-8')
                print(f"Message déchiffré par le serveur : '{decrypted_message}'")
                print("Test de chiffrement/déchiffrement réussi !")
            else:
                print(f"Erreur du serveur : {response['message']}")
                
    except ConnectionRefusedError:
        print(f"Erreur : Impossible de se connecter au serveur à {SERVER_HOST}:{SERVER_PORT}. Assurez-vous que le serveur est en cours d'exécution.")
    except Exception as e:
        print(f"Une erreur est survenue : {e}")
        
if __name__ == "__main__":
    run_client()