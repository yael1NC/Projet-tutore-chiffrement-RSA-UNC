import ctypes
import os
import socket
import json

KEY_DIR = "keys"
PUB_N_FILE = os.path.join(KEY_DIR, "public_n.key")
PUB_E_FILE = os.path.join(KEY_DIR, "public_e.key")
PRIV_D_FILE = os.path.join(KEY_DIR, "private_d.key")

try:
    rsa_lib = ctypes.CDLL('./rsa_lib.so')
except OSError as e:
    print(f"Erreur : Impossible de charger la bibliothèque C rsa_lib.so. Détails : {e}")
    exit(1)

rsa_lib.generate_rsa_keys.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
rsa_lib.generate_rsa_keys.restype = None

rsa_lib.rsa_encrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
rsa_lib.rsa_encrypt_string.restype = None

rsa_lib.rsa_decrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
rsa_lib.rsa_decrypt_string.restype = None

rsa_lib.rsa_sign_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
rsa_lib.rsa_sign_string.restype = None

rsa_lib.rsa_verify_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
rsa_lib.rsa_verify_string.restype = ctypes.c_int

BUFFER_SIZE = 8192

def rsa_encrypt_python(non_encrypt_hex, e_hex, n_hex):
    encrypt_message_hex_out = ctypes.create_string_buffer(BUFFER_SIZE)
    rsa_lib.rsa_encrypt_string(non_encrypt_hex.encode('utf-8'), e_hex.encode('utf-8'), n_hex.encode('utf-8'), encrypt_message_hex_out, BUFFER_SIZE)
    return encrypt_message_hex_out.value.decode('utf-8')

def rsa_decrypt_python(encrypt_message_hex, d_hex, n_hex):
    non_encrypt_hex_out = ctypes.create_string_buffer(BUFFER_SIZE)
    rsa_lib.rsa_decrypt_string(encrypt_message_hex.encode('utf-8'), d_hex.encode('utf-8'), n_hex.encode('utf-8'), non_encrypt_hex_out, BUFFER_SIZE)
    return non_encrypt_hex_out.value.decode('utf-8')

def rsa_sign_python(message_hash_hex, d_hex, n_hex):
    signature_hex_out = ctypes.create_string_buffer(BUFFER_SIZE)
    rsa_lib.rsa_sign_string(message_hash_hex.encode('utf-8'), d_hex.encode('utf-8'), n_hex.encode('utf-8'), signature_hex_out, BUFFER_SIZE)
    return signature_hex_out.value.decode('utf-8')

def rsa_verify_python(message_hash_hex, signature_hex, e_hex, n_hex):
    return rsa_lib.rsa_verify_string(message_hash_hex.encode('utf-8'), signature_hex.encode('utf-8'), e_hex.encode('utf-8'), n_hex.encode('utf-8'))

def load_or_generate_keys():
    print("Vérification des fichiers de clés...")
    if (os.path.exists(PUB_N_FILE) and
        os.path.exists(PUB_E_FILE) and
        os.path.exists(PRIV_D_FILE)):
        print("Clés existantes trouvées. Chargement...")
        with open(PUB_N_FILE, 'r') as f:
            n_val = f.read()
        with open(PUB_E_FILE, 'r') as f:
            e_val = f.read()
        with open(PRIV_D_FILE, 'r') as f:
            d_val = f.read()
        print("Clés chargées avec succès.")
        return n_val, e_val, d_val

    print("Aucune clé trouvée, ou fichiers incomplets.")
    print("Génération de nouvelles clés...")
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)
        
    n_out = ctypes.create_string_buffer(BUFFER_SIZE)
    d_out = ctypes.create_string_buffer(BUFFER_SIZE)

    rsa_lib.generate_rsa_keys(n_out, d_out, BUFFER_SIZE)

    n_val = n_out.value.decode('utf-8')
    d_val = d_out.value.decode('utf-8')
    e_val = '10001' # exposant public standard

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

HOST = '0.0.0.0'  # Écoute sur toutes les interfaces réseau
PORT = 65432      # Port arbitraire

def handle_client(conn, addr, d_val, n_val, e_val):
    """Gère la connexion d'un client."""
    print(f"Connecté par {addr}")
    try:
        data = conn.recv(4096).decode('utf-8')
        request = json.loads(data)

        operation = request.get('operation')
        payload = request.get('data')

        response = {}
        if operation == 'decrypt':
            print(f"Requête de déchiffrement reçue.")
            decrypted_data = rsa_decrypt_python(payload, d_val, n_val)
            response['result'] = decrypted_data
            response['status'] = 'success'
        elif operation == 'verify':
            print(f"Requête de vérification reçue.")
            is_valid = rsa_verify_python(payload['hash'], payload['signature'], e_val, n_val)
            response['result'] = is_valid
            response['status'] = 'success'
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
        s.bind((HOST, PORT))
        s.listen()
        print(f"Serveur démarré et écoutant sur {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            handle_client(conn, addr, d_val, n_val, e_val)

if __name__ == "__main__":
    run_server()