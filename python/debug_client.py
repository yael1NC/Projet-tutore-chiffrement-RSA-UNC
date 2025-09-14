#!/usr/bin/env python3
"""
Version debug du client pour diagnostiquer les problèmes de communication
"""

import socket
import json
import ctypes
import os
import time
import sys
from key_manager import SecureKeyManager

# Configuration du client
SERVER_HOST = '192.168.0.141'  # Votre adresse serveur
SERVER_PORT = 65432
BUFFER_SIZE = 8192
KEY_DIR = "client_keys"

# Chargement de la bibliothèque RSA
try:
    lib_path = os.path.join(os.path.dirname(__file__), '..', 'rsa_lib.so')
    if not os.path.exists(lib_path):
        lib_path = './rsa_lib.so'
    rsa_lib = ctypes.CDLL(os.path.abspath(lib_path))
except OSError as e:
    print(f"Erreur : Impossible de charger la bibliothèque C rsa_lib.so. Détails : {e}")
    exit(1)

# Configuration des signatures des fonctions
rsa_lib.rsa_encrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
rsa_lib.rsa_encrypt_string.restype = None


def debug_rsa_encrypt(message, e_hex, n_hex, algo_choice=6):
    """Version debug du chiffrement RSA"""
    print(f"DEBUG: Chiffrement du message")
    print(f"  Message: '{message}' ({len(message)} caractères)")
    print(f"  E: {e_hex}")
    print(f"  N: {n_hex[:50]}...")
    print(f"  Algorithme: {algo_choice}")
    
    encrypt_message_hex_out = ctypes.create_string_buffer(BUFFER_SIZE)
    
    try:
        rsa_lib.rsa_encrypt_string(
            message.encode('utf-8'),
            e_hex.encode('utf-8'), 
            n_hex.encode('utf-8'), 
            encrypt_message_hex_out, 
            BUFFER_SIZE, 
            algo_choice
        )
        
        result = encrypt_message_hex_out.value.decode('utf-8')
        print(f"  Résultat: {len(result)} caractères hex")
        print(f"  Début: {result[:100]}...")
        return result
        
    except Exception as e:
        print(f"ERREUR lors du chiffrement: {e}")
        return None


def debug_send_request(server_host, server_port, operation, data=None):
    """Version debug de l'envoi de requête"""
    print(f"\nDEBUG: Envoi de requête")
    print(f"  Serveur: {server_host}:{server_port}")
    print(f"  Opération: {operation}")
    
    if data:
        print(f"  Données: {len(data)} caractères")
        print(f"  Début données: {data[:100]}...")
    
    request_data = {
        'operation': operation,
        'data': data,
        'timestamp': time.time()
    }
    
    request_json = json.dumps(request_data)
    print(f"  JSON à envoyer: {len(request_json)} caractères")
    print(f"  Début JSON: {request_json[:200]}...")
    
    sock = None
    try:
        # Connexion
        print("  Tentative de connexion...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)  # Timeout plus long pour debug
        sock.connect((server_host, server_port))
        print("  ✅ Connexion établie")
        
        # Envoi
        print("  Envoi des données...")
        bytes_sent = sock.sendall(request_json.encode('utf-8'))
        print(f"  ✅ Données envoyées")
        
        # Réception
        print("  Attente de la réponse...")
        response_data = sock.recv(4096)
        print(f"  ✅ Réponse reçue: {len(response_data)} bytes")
        
        # Décodage
        try:
            response_str = response_data.decode('utf-8')
            print(f"  Réponse brute: {response_str[:500]}...")
            
            response = json.loads(response_str)
            print(f"  ✅ JSON valide décodé")
            return response
            
        except json.JSONDecodeError as e:
            print(f"  ❌ ERREUR JSON: {e}")
            print(f"  Réponse brute: {response_data}")
            return None
            
    except socket.timeout:
        print("  ❌ TIMEOUT de connexion")
        return None
    except ConnectionRefusedError:
        print("  ❌ CONNEXION REFUSÉE")
        return None
    except Exception as e:
        print(f"  ❌ ERREUR: {e}")
        return None
    finally:
        if sock:
            sock.close()
            print("  Connexion fermée")


def test_server_connectivity():
    """Test de connectivité avec le serveur"""
    print("=" * 60)
    print("TEST DE CONNECTIVITÉ")
    print("=" * 60)
    
    # Test ping (si disponible)
    try:
        import subprocess
        result = subprocess.run(['ping', '-c', '1', SERVER_HOST], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"✅ Ping vers {SERVER_HOST} réussi")
        else:
            print(f"❌ Ping vers {SERVER_HOST} échoué")
    except:
        print("⚠️  Test ping non disponible")
    
    # Test de connexion socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((SERVER_HOST, SERVER_PORT))
        sock.close()
        
        if result == 0:
            print(f"✅ Connexion socket vers {SERVER_HOST}:{SERVER_PORT} réussie")
            return True
        else:
            print(f"❌ Connexion socket échouée (code {result})")
            return False
    except Exception as e:
        print(f"❌ Erreur de connexion: {e}")
        return False


def test_server_info():
    """Test de récupération des informations serveur"""
    print("\n" + "=" * 60)
    print("TEST INFORMATIONS SERVEUR")
    print("=" * 60)
    
    response = debug_send_request(SERVER_HOST, SERVER_PORT, 'server_info')
    
    if response:
        print("✅ Informations serveur récupérées:")
        for key, value in response.items():
            print(f"  {key}: {value}")
        return True
    else:
        print("❌ Impossible de récupérer les informations serveur")
        return False


def test_public_keys():
    """Test de récupération des clés publiques"""
    print("\n" + "=" * 60)
    print("TEST CLÉS PUBLIQUES")
    print("=" * 60)
    
    response = debug_send_request(SERVER_HOST, SERVER_PORT, 'get_public_key')
    
    if response and response.get('status') == 'success':
        n = response.get('n', '')
        e = response.get('e', '')
        print("✅ Clés publiques récupérées:")
        print(f"  N: {n[:50]}... ({len(n)} caractères)")
        print(f"  E: {e}")
        return n, e
    else:
        print("❌ Impossible de récupérer les clés publiques")
        if response:
            print(f"  Réponse: {response}")
        return None, None


def test_encryption_decryption(message, n_val, e_val):
    """Test complet de chiffrement/déchiffrement"""
    print("\n" + "=" * 60)
    print("TEST CHIFFREMENT/DÉCHIFFREMENT")
    print("=" * 60)
    
    # Chiffrement
    encrypted = debug_rsa_encrypt(message, e_val, n_val)
    if not encrypted:
        return False
    
    # Test de déchiffrement
    response = debug_send_request(SERVER_HOST, SERVER_PORT, 'decrypt', encrypted)
    
    if response and response.get('status') == 'success':
        decrypted = response.get('result', '')
        print(f"✅ Message déchiffré: '{decrypted}'")
        
        if message == decrypted:
            print("✅ Test de chiffrement/déchiffrement réussi!")
            return True
        else:
            print("❌ Les messages ne correspondent pas")
            print(f"  Original:  '{message}'")
            print(f"  Déchiffré: '{decrypted}'")
            return False
    else:
        print("❌ Erreur lors du déchiffrement")
        if response:
            print(f"  Réponse: {response}")
        return False


def main():
    """Fonction principale de debug"""
    print("=" * 60)
    print("CLIENT RSA SÉCURISÉ - MODE DEBUG")
    print("=" * 60)
    print(f"Serveur cible: {SERVER_HOST}:{SERVER_PORT}")
    
    # Test 1: Connectivité
    if not test_server_connectivity():
        print("\n❌ ÉCHEC: Problème de connectivité réseau")
        return
    
    # Test 2: Informations serveur
    if not test_server_info():
        print("\n❌ ÉCHEC: Impossible de communiquer avec le serveur")
        return
    
    # Test 3: Clés publiques
    n_val, e_val = test_public_keys()
    if not n_val or not e_val:
        print("\n❌ ÉCHEC: Impossible de récupérer les clés publiques")
        return
    
    # Test 4: Messages de différentes tailles
    test_messages = [
        "Test",
        "Message court",
        "Message de taille moyenne pour tester",
        "Bonjour,voici le message a chiffrer puis a dechiffrer"
    ]
    
    for i, message in enumerate(test_messages, 1):
        print(f"\n{'='*20} TEST {i}/4 {'='*20}")
        success = test_encryption_decryption(message, n_val, e_val)
        if not success:
            print(f"❌ ÉCHEC pour le message {i}: '{message}'")
        else:
            print(f"✅ SUCCÈS pour le message {i}")
    
    print("\n" + "=" * 60)
    print("TESTS TERMINÉS")
    print("=" * 60)


if __name__ == "__main__":
    main()