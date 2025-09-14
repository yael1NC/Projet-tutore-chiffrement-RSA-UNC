#!/usr/bin/env python3
"""
Client RSA sécurisé avec gestion automatique des clés publiques
Récupère automatiquement les clés publiques du serveur
"""

import socket
import json
import ctypes
import os
import time
from key_manager import SecureKeyManager

# Configuration du client
SERVER_HOST = '127.0.0.1'  # Remplacez par l'IP du serveur
SERVER_PORT = 65432
BUFFER_SIZE = 8192
KEY_DIR = "client_keys"

# Chargement de la bibliothèque RSA
try:
    lib_path = os.path.join(os.path.dirname(__file__), '..', 'rsa_lib.so')
    rsa_lib = ctypes.CDLL(os.path.abspath(lib_path))
except OSError as e:
    print(f"Erreur : Impossible de charger la bibliothèque C rsa_lib.so. Détails : {e}")
    exit(1)

# Configuration des signatures des fonctions
rsa_lib.rsa_encrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
rsa_lib.rsa_encrypt_string.restype = None


class SecureRSAClient:
    def __init__(self, server_host=SERVER_HOST, server_port=SERVER_PORT):
        self.server_host = server_host
        self.server_port = server_port
        self.public_key_cache = os.path.join(KEY_DIR, "server_public_keys.json")
        self.n_val = None
        self.e_val = None
        
        # Créer le dossier des clés client
        if not os.path.exists(KEY_DIR):
            os.makedirs(KEY_DIR, mode=0o700)
    
    def rsa_encrypt_python(self, message, e_hex, n_hex, algo_choice=6):
        """Chiffre un message texte avec RSA"""
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
    
    def connect_to_server(self):
        """Établit une connexion avec le serveur"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # Timeout de 10 secondes
            sock.connect((self.server_host, self.server_port))
            return sock
        except Exception as e:
            print(f"Erreur de connexion au serveur {self.server_host}:{self.server_port}: {e}")
            return None
    
    def send_request(self, operation, data=None):
        """Envoie une requête au serveur et retourne la réponse"""
        request_data = {
            'operation': operation,
            'data': data,
            'timestamp': time.time()
        }
        
        sock = self.connect_to_server()
        if not sock:
            return None
        
        try:
            # Envoi de la requête
            request_json = json.dumps(request_data)
            sock.sendall(request_json.encode('utf-8'))
            
            # Réception de la réponse
            response_data = sock.recv(4096)
            response = json.loads(response_data.decode('utf-8'))
            
            return response
            
        except Exception as e:
            print(f"Erreur lors de la communication: {e}")
            return None
        finally:
            sock.close()
    
    def get_server_info(self):
        """Récupère les informations du serveur"""
        print("Récupération des informations du serveur...")
        response = self.send_request('server_info')
        
        if response and response.get('status') == 'success':
            info = response.get('info', {})
            print("Informations du serveur:")
            print(f"  Version: {info.get('version', 'Inconnue')}")
            print(f"  Protection des clés: {info.get('key_protection', 'Inconnue')}")
            print(f"  Opérations supportées: {', '.join(info.get('supported_operations', []))}")
            return True
        else:
            print("Impossible de récupérer les informations du serveur")
            return False
    
    def fetch_public_keys(self):
        """Récupère les clés publiques du serveur"""
        print("Récupération des clés publiques du serveur...")
        
        response = self.send_request('get_public_key')
        
        if response and response.get('status') == 'success':
            self.n_val = response.get('n')
            self.e_val = response.get('e')
            
            if self.n_val and self.e_val:
                # Sauvegarder les clés publiques en cache
                cache_data = {
                    'n': self.n_val,
                    'e': self.e_val,
                    'server': f"{self.server_host}:{self.server_port}",
                    'retrieved_at': time.time()
                }
                
                with open(self.public_key_cache, 'w') as f:
                    json.dump(cache_data, f, indent=2)
                
                print("Clés publiques récupérées et mises en cache:")
                print(f"  N: {self.n_val[:50]}...")
                print(f"  E: {self.e_val}")
                return True
            else:
                print("Clés publiques incomplètes reçues")
                return False
        else:
            print("Erreur lors de la récupération des clés publiques")
            return False
    
    def load_cached_public_keys(self):
        """Charge les clés publiques depuis le cache"""
        if os.path.exists(self.public_key_cache):
            try:
                with open(self.public_key_cache, 'r') as f:
                    cache_data = json.load(f)
                
                # Vérifier si les clés correspondent au serveur actuel
                cached_server = cache_data.get('server', '')
                current_server = f"{self.server_host}:{self.server_port}"
                
                if cached_server == current_server:
                    self.n_val = cache_data.get('n')
                    self.e_val = cache_data.get('e')
                    
                    if self.n_val and self.e_val:
                        print("Clés publiques chargées depuis le cache")
                        retrieved_at = cache_data.get('retrieved_at', 0)
                        print(f"  Récupérées le: {time.ctime(retrieved_at)}")
                        return True
                
            except Exception as e:
                print(f"Erreur lors du chargement du cache: {e}")
        
        return False
    
    def ensure_public_keys(self):
        """S'assure que les clés publiques sont disponibles"""
        # Essayer de charger depuis le cache
        if self.load_cached_public_keys():
            return True
        
        # Sinon, récupérer du serveur
        return self.fetch_public_keys()
    
    def encrypt_and_send_message(self, message, algo_choice=6):
        """Chiffre et envoie un message au serveur pour déchiffrement"""
        if not self.ensure_public_keys():
            print("Impossible d'obtenir les clés publiques du serveur")
            return False
        
        print(f"Message original : '{message}'")
        
        try:
            # Chiffrement du message
            print("Chiffrement du message...")
            encrypted_msg_hex = self.rsa_encrypt_python(message, self.e_val, self.n_val, algo_choice)
            print(f"Message chiffré (hex) : {encrypted_msg_hex[:50]}...")
            
            # Envoi au serveur pour déchiffrement
            print("Envoi au serveur pour déchiffrement...")
            response = self.send_request('decrypt', encrypted_msg_hex)
            
            if response and response.get('status') == 'success':
                decrypted_message = response.get('result')
                print(f"Message déchiffré par le serveur : '{decrypted_message}'")
                
                # Vérification
                if message == decrypted_message:
                    print("Test de chiffrement/déchiffrement réussi !")
                    return True
                else:
                    print("Erreur : Le message déchiffré ne correspond pas à l'original")
                    print(f"Original: '{message}'")
                    print(f"Déchiffré: '{decrypted_message}'")
                    return False
            else:
                error_msg = response.get('message', 'Erreur inconnue') if response else 'Pas de réponse'
                print(f"Erreur du serveur : {error_msg}")
                return False
                
        except Exception as e:
            print(f"Erreur lors du chiffrement ou de l'envoi : {e}")
            return False
    
    def interactive_mode(self):
        """Mode interactif pour tester le client"""
        print("=" * 60)
        print("  CLIENT RSA SÉCURISÉ - MODE INTERACTIF")
        print("=" * 60)
        print(f"Serveur cible: {self.server_host}:{self.server_port}")
        
        # Récupérer les informations du serveur
        self.get_server_info()
        
        while True:
            print("\n" + "=" * 50)
            print("  MENU CLIENT")
            print("=" * 50)
            print("1. Tester le chiffrement/déchiffrement")
            print("2. Rafraîchir les clés publiques")
            print("3. Afficher les clés publiques")
            print("4. Changer l'adresse du serveur")
            print("5. Test de performance")
            print("6. Quitter")
            print("=" * 50)
            
            try:
                choice = input("Votre choix : ").strip()
                
                if choice == '1':
                    message = input("Entrez le message à tester : ")
                    if message:
                        self.encrypt_and_send_message(message)
                    else:
                        print("Message vide !")
                
                elif choice == '2':
                    if self.fetch_public_keys():
                        print("Clés publiques mises à jour")
                    else:
                        print("Échec de la mise à jour")
                
                elif choice == '3':
                    if self.ensure_public_keys():
                        print("Clés publiques actuelles:")
                        print(f"  N: {self.n_val[:50]}...")
                        print(f"  E: {self.e_val}")
                    else:
                        print("Aucune clé publique disponible")
                
                elif choice == '4':
                    new_host = input(f"Nouvelle adresse IP ({self.server_host}): ").strip()
                    new_port = input(f"Nouveau port ({self.server_port}): ").strip()
                    
                    if new_host:
                        self.server_host = new_host
                    if new_port:
                        try:
                            self.server_port = int(new_port)
                        except ValueError:
                            print("Port invalide")
                            continue
                    
                    print(f"Nouveau serveur: {self.server_host}:{self.server_port}")
                    # Invalider le cache
                    if os.path.exists(self.public_key_cache):
                        os.remove(self.public_key_cache)
                
                elif choice == '5':
                    self.performance_test()
                
                elif choice == '6':
                    print("Au revoir !")
                    break
                
                else:
                    print("Choix invalide")
                    
            except KeyboardInterrupt:
                print("\n\nAu revoir !")
                break
            except Exception as e:
                print(f"Erreur : {e}")
    
    def performance_test(self):
        """Test de performance avec différents algorithmes"""
        messages = [
            "Test court",
            "Message de longueur moyenne pour tester les performances",
            "Message très long pour évaluer les performances du système de chiffrement RSA avec différents algorithmes d'exponentiation modulaire"
        ]
        
        algorithms = {
            1: "Square and Multiply",
            2: "Square and Multiply Always", 
            3: "Montgomery Ladder",
            4: "Semi-interleaved Ladder",
            5: "Fully-interleaved Ladder",
            6: "GMP mpz_powm (défaut)"
        }
        
        print("\nTest de performance des algorithmes de chiffrement:")
        print("=" * 60)
        
        for i, message in enumerate(messages, 1):
            print(f"\nTest {i} - Message: '{message[:30]}{'...' if len(message) > 30 else ''}'")
            print("-" * 50)
            
            for algo_num, algo_name in algorithms.items():
                print(f"Algorithme {algo_num} ({algo_name}):", end=" ")
                
                start_time = time.time()
                success = self.encrypt_and_send_message(message, algo_num)
                elapsed_time = time.time() - start_time
                
                if success:
                    print(f"Réussi en {elapsed_time:.3f}s")
                else:
                    print("Échec")
    
    def simple_test(self, message="Hello RSA Secure!"):
        """Test simple et rapide"""
        print("=" * 50)
        print("  TEST RAPIDE CLIENT RSA SÉCURISÉ")
        print("=" * 50)
        
        return self.encrypt_and_send_message(message)


def main():
    """Fonction principale"""
    import sys
    
    client = SecureRSAClient()
    
    if len(sys.argv) > 1:
        # Mode test rapide avec message personnalisé
        message = " ".join(sys.argv[1:])
        client.simple_test(message)
    else:
        # Mode interactif
        client.interactive_mode()


if __name__ == "__main__":
    main()