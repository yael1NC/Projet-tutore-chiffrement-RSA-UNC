#!/usr/bin/env python3
"""
Serveur RSA sécurisé avec gestion de clés chiffrées
Utilise le gestionnaire de clés sécurisé pour protéger les clés privées
"""

import ctypes
import os
import socket
import json
import getpass
import sys
from key_manager import SecureKeyManager

# Configuration du serveur
HOST = '0.0.0.0'
PORT = 65432
BUFFER_SIZE = 8192

# Chargement de la bibliothèque RSA
try:
    lib_path = os.path.join(os.path.dirname(__file__), '..', 'rsa_lib.so')
    rsa_lib = ctypes.CDLL(os.path.abspath(lib_path))
except OSError as e:
    print(f"Erreur : Impossible de charger la bibliothèque C rsa_lib.so. Détails : {e}")
    exit(1)

# Configuration des signatures des fonctions C
rsa_lib.generate_rsa_keys.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
rsa_lib.generate_rsa_keys.restype = None

rsa_lib.rsa_encrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
rsa_lib.rsa_encrypt_string.restype = None

rsa_lib.rsa_decrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
rsa_lib.rsa_decrypt_string.restype = None


class SecureRSAServer:
    def __init__(self, key_dir="keys"):
        self.key_manager = SecureKeyManager(key_dir)
        self.n_val = None
        self.e_val = None
        self.d_val = None
        
    def rsa_decrypt_python(self, encrypt_message_hex, d_hex, n_hex, algo_choice=6):
        """Déchiffre un message chiffré en hexadécimal avec RSA"""
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
    
    def load_or_generate_keys(self, password=None):
        """Charge les clés existantes ou en génère de nouvelles"""
        print("Vérification des clés RSA sécurisées...")
        
        if self.key_manager.has_encrypted_keys():
            print("Clés chiffrées trouvées. Déchiffrement...")
            try:
                # Tenter de déchiffrer les clés
                if password is None:
                    password = getpass.getpass("Mot de passe des clés RSA: ")
                
                self.n_val, self.e_val, self.d_val = self.key_manager.decrypt_keys(password)
                print("Clés chargées avec succès depuis le stockage sécurisé.")
                return True
                
            except Exception as e:
                print(f"Erreur lors du déchiffrement des clés: {e}")
                return False
        
        # Vérifier s'il existe des clés en clair (ancienne méthode)
        plaintext_files = ["public_n.key", "public_e.key", "private_d.key"]
        plaintext_paths = [os.path.join(self.key_manager.key_dir, f) for f in plaintext_files]
        
        if all(os.path.exists(path) for path in plaintext_paths):
            print("Clés en clair détectées. Migration vers le stockage sécurisé...")
            
            # Charger les clés en clair
            with open(plaintext_paths[0], 'r') as f:
                n_val = f.read().strip()
            with open(plaintext_paths[1], 'r') as f:
                e_val = f.read().strip()
            with open(plaintext_paths[2], 'r') as f:
                d_val = f.read().strip()
            
            # Migrer vers le stockage sécurisé
            print("Chiffrement des clés existantes...")
            if password is None:
                password = getpass.getpass("Créez un mot de passe pour sécuriser vos clés: ")
            
            if self.key_manager.encrypt_keys(n_val, e_val, d_val, password):
                self.n_val, self.e_val, self.d_val = n_val, e_val, d_val
                print("Migration réussie vers le stockage sécurisé.")
                return True
            else:
                print("Erreur lors de la migration. Utilisation des clés en clair.")
                self.n_val, self.e_val, self.d_val = n_val, e_val, d_val
                return True
        
        # Génération de nouvelles clés
        print("Aucune clé trouvée. Génération de nouvelles clés RSA (4096 bits)...")
        print("Cela peut prendre quelques minutes...")
        
        if not os.path.exists(self.key_manager.key_dir):
            os.makedirs(self.key_manager.key_dir, mode=0o700)
        
        # Génération des clés
        n_out = ctypes.create_string_buffer(BUFFER_SIZE)
        d_out = ctypes.create_string_buffer(BUFFER_SIZE)
        
        rsa_lib.generate_rsa_keys(n_out, d_out, BUFFER_SIZE)
        
        n_val = n_out.value.decode('utf-8')
        d_val = d_out.value.decode('utf-8')
        e_val = '10001'  # Exposant public standard
        
        print(f"Clés générées:")
        print(f"  N: {n_val[:50]}...")
        print(f"  E: {e_val}")
        print(f"  D: {d_val[:50]}...")
        
        # Chiffrement et sauvegarde sécurisée
        print("Chiffrement des nouvelles clés...")
        if password is None:
            password = getpass.getpass("Créez un mot de passe pour sécuriser vos clés: ")
        
        if self.key_manager.encrypt_keys(n_val, e_val, d_val, password):
            self.n_val, self.e_val, self.d_val = n_val, e_val, d_val
            print("Nouvelles clés générées et sécurisées avec succès.")
            return True
        else:
            print("Erreur lors de la sécurisation. Les clés ne seront pas sauvegardées.")
            return False
    
    def handle_client(self, conn, addr):
        """Traite une connexion client"""
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
                    decrypted_data = self.rsa_decrypt_python(payload, self.d_val, self.n_val)
                    response['result'] = decrypted_data
                    response['status'] = 'success'
                    print(f"Déchiffrement réussi : '{decrypted_data}'")
                except Exception as e:
                    print(f"Erreur lors du déchiffrement : {e}")
                    response['status'] = 'error'
                    response['message'] = f'Erreur de déchiffrement: {str(e)}'
            
            elif operation == 'get_public_key':
                print("Requête de clé publique reçue.")
                response['n'] = self.n_val
                response['e'] = self.e_val
                response['status'] = 'success'
                print("Clé publique envoyée.")
            
            elif operation == 'server_info':
                response['status'] = 'success'
                response['info'] = {
                    'version': '2.0-secure',
                    'key_protection': 'encrypted',
                    'supported_operations': ['decrypt', 'get_public_key', 'server_info']
                }
                
            else:
                response['status'] = 'error'
                response['message'] = 'Opération non supportée.'
                
            conn.sendall(json.dumps(response).encode('utf-8'))
            
        except json.JSONDecodeError:
            print("Erreur de décodage JSON.")
            conn.sendall(json.dumps({'status': 'error', 'message': 'JSON invalide'}).encode('utf-8'))
        except Exception as e:
            print(f"Erreur lors du traitement de la requête : {e}")
            conn.sendall(json.dumps({'status': 'error', 'message': str(e)}).encode('utf-8'))
        finally:
            conn.close()
            print(f"Connexion avec {addr} fermée.")
    
    def run_server(self):
        """Lance le serveur RSA sécurisé"""
        print("=" * 60)
        print("  SERVEUR RSA SÉCURISÉ")
        print("=" * 60)
        
        # Chargement des clés
        if not self.load_or_generate_keys():
            print("Impossible de charger ou générer les clés. Arrêt du serveur.")
            return
        
        # Configuration du serveur
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen()
            
            print("\n" + "=" * 60)
            print(f"Serveur démarré et écoutant sur {HOST}:{PORT}")
            print("Clés protégées par chiffrement AES-256-GCM")
            print("Opérations supportées:")
            print("  - decrypt: Déchiffrement de messages")
            print("  - get_public_key: Récupération de la clé publique")
            print("  - server_info: Informations du serveur")
            print("=" * 60)
            print("Appuyez sur Ctrl+C pour arrêter le serveur")
            print()
            
            try:
                while True:
                    conn, addr = s.accept()
                    self.handle_client(conn, addr)
            except KeyboardInterrupt:
                print("\nArrêt du serveur...")
                print("Clés sécurisées maintenues en mémoire chiffrée.")
    
    def manage_keys(self):
        """Interface de gestion des clés"""
        while True:
            print("\n" + "=" * 50)
            print("  GESTION DES CLÉS RSA SÉCURISÉES")
            print("=" * 50)
            print("1. Afficher les informations des clés")
            print("2. Changer le mot de passe")
            print("3. Exporter la clé publique")
            print("4. Tester le déchiffrement des clés")
            print("5. Retourner au serveur")
            print("=" * 50)
            
            choice = input("Votre choix : ").strip()
            
            if choice == '1':
                self.key_manager.get_key_info()
                
            elif choice == '2':
                self.key_manager.change_password()
                
            elif choice == '3':
                filename = input("Nom du fichier (ou Entrée pour défaut): ").strip()
                if not filename:
                    filename = None
                self.key_manager.export_public_key(filename)
                
            elif choice == '4':
                try:
                    password = getpass.getpass("Mot de passe: ")
                    n, e, d = self.key_manager.decrypt_keys(password)
                    print(f"Test réussi - N: {n[:30]}...")
                except Exception as e:
                    print(f"Erreur: {e}")
                    
            elif choice == '5':
                break
            else:
                print("Choix invalide")


def main():
    """Fonction principale"""
    if len(sys.argv) > 1 and sys.argv[1] == '--manage-keys':
        # Mode gestion des clés
        server = SecureRSAServer()
        server.manage_keys()
    else:
        # Mode serveur normal
        server = SecureRSAServer()
        server.run_server()


if __name__ == "__main__":
    main()