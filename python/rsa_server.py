import ctypes
import os
import socket
import json

# Nouvelle ligne de code pour charger la bibliothèque C depuis le répertoire parent
try:
    # Le chemin est maintenant relatif à la racine du projet
    lib_path = os.path.join(os.path.dirname(__file__), '..', 'rsa_lib.so')
    rsa_lib = ctypes.CDLL(os.path.abspath(lib_path))
except OSError as e:
    print(f"Erreur : Impossible de charger la bibliothèque C rsa_lib.so. Détails : {e}")
    exit(1)

# Configuration des chemins de fichiers pour les clés (inchangé)
KEY_DIR = "keys"
PUB_N_FILE = os.path.join(KEY_DIR, "public_n.key")
PUB_E_FILE = os.path.join(KEY_DIR, "public_e.key")
PRIV_D_FILE = os.path.join(KEY_DIR, "private_d.key")

# Définir les signatures des fonctions C (inchangé)
rsa_lib.generate_rsa_keys.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
rsa_lib.generate_rsa_keys.restype = None

rsa_lib.rsa_encrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
rsa_lib.rsa_encrypt_string.restype = None

rsa_lib.rsa_decrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
rsa_lib.rsa_decrypt_string.restype = None

BUFFER_SIZE = 8192

# Fonctions Python pour l'interface C
def rsa_encrypt_python(message, e_hex, n_hex, algo_choice=6):
    """
    Chiffre un message texte avec RSA
    """
    encrypt_message_hex_out = ctypes.create_string_buffer(BUFFER_SIZE)
    rsa_lib.rsa_encrypt_string(
        message.encode('utf-8'), 
        e_hex.encode('utf-8'), 
        n_hex.encode('utf-8'), 
        encrypt_message_hex_out, 
        BUFFER_SIZE, 
        algo_choice
    )
    return encrypt_message_hex_out.value.decode('utf-8')

def rsa_decrypt_python(encrypt_message_hex, d_hex, n_hex, algo_choice=6):
    """
    Déchiffre un message chiffré en hexadécimal avec RSA
    """
    non_encrypt_out = ctypes.create_string_buffer(BUFFER_SIZE)
    rsa_lib.rsa_decrypt_string(
        encrypt_message_hex.encode('utf-8'), 
        d_hex.encode('utf-8'), 
        n_hex.encode('utf-8'), 
        non_encrypt_out, 
        BUFFER_SIZE, 
        algo_choice
    )
    return non_encrypt_out.value.decode('utf-8')

# Fonctions de gestion de clés
def load_or_generate_keys():
    print("Vérification des fichiers de clés...")
    if (os.path.exists(PUB_N_FILE) and
        os.path.exists(PUB_E_FILE) and
        os.path.exists(PRIV_D_FILE)):
        print("Clés existantes trouvées. Chargement...")
        with open(PUB_N_FILE, 'r') as f:
            n_val = f.read().strip()
        with open(PUB_E_FILE, 'r') as f:
            e_val = f.read().strip()
        with open(PRIV_D_FILE, 'r') as f:
            d_val = f.read().strip()
        print("Clés chargées avec succès.")
        return n_val, e_val, d_val

    print("Aucune clé trouvée, ou fichiers incomplets.")
    print("Génération de nouvelles clés...")
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)
        
    n_out = ctypes.create_string_buffer(BUFFER_SIZE)
    d_out = ctypes.create_string_buffer(BUFFER_SIZE)

    print("Génération en cours... (cela peut prendre quelques minutes)")
    rsa_lib.generate_rsa_keys(n_out, d_out, BUFFER_SIZE)

    n_val = n_out.value.decode('utf-8')
    d_val = d_out.value.decode('utf-8')
    e_val = '10001'  # exposant public standard

    print(f"Clé publique générée (N, E) : ({n_val[:50]}..., {e_val})")
    print(f"Clé privée générée (D) : ({d_val[:50]}...)")
    
    with open(PUB_N_FILE, 'w') as f:
        f.write(n_val)
    with open(PUB_E_FILE, 'w') as f:
        f.write(e_val)
    with open(PRIV_D_FILE, 'w') as f:
        f.write(d_val)
    
    print("Clés sauvegardées avec succès.")
    return n_val, e_val, d_val


# Logique du serveur
HOST = '0.0.0.0'
PORT = 65432

def handle_client(conn, addr, d_val, n_val, e_val):
    print(f"Connecté par {addr}")
    try:
        data = conn.recv(4096).decode('utf-8')
        request = json.loads(data)
        operation = request.get('operation')
        payload = request.get('data')
        response = {}
        
        if operation == 'decrypt':
            print(f"Requête de déchiffrement reçue.")
            try:
                decrypted_data = rsa_decrypt_python(payload, d_val, n_val)
                response['result'] = decrypted_data
                response['status'] = 'success'
                print(f"Déchiffrement réussi : '{decrypted_data}'")
            except Exception as e:
                print(f"Erreur lors du déchiffrement : {e}")
                response['status'] = 'error'
                response['message'] = f'Erreur de déchiffrement: {str(e)}'
        else:
            response['status'] = 'error'
            response['message'] = 'Opération non supportée.'
            
        conn.sendall(json.dumps(response).encode('utf-8'))
        
    except json.JSONDecodeError:
        print("Erreur de décodage JSON.")
        conn.sendall(json.dumps({'status': 'error', 'message': 'Invalid JSON'}).encode('utf-8'))
    except Exception as e:
        print(f"Erreur lors du traitement de la requête : {e}")
        conn.sendall(json.dumps({'status': 'error', 'message': str(e)}).encode('utf-8'))
    finally:
        conn.close()
        print(f"Connexion avec {addr} fermée.")

def run_server():
    n_val, e_val, d_val = load_or_generate_keys()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Permet de redémarrer rapidement
        s.bind((HOST, PORT))
        s.listen()
        print(f"Serveur démarré et écoutant sur {HOST}:{PORT}")
        try:
            while True:
                conn, addr = s.accept()
                handle_client(conn, addr, d_val, n_val, e_val)
        except KeyboardInterrupt:
            print("\nArrêt du serveur...")

if __name__ == "__main__":
    run_server()