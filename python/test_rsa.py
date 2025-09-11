#!/usr/bin/env python3
"""
Script de test simple pour vérifier le bon fonctionnement de la bibliothèque RSA
"""

import ctypes
import os

# Chargement de la bibliothèque
try:
    lib_path = os.path.join(os.path.dirname(__file__), '..', 'rsa_lib.so')
    rsa_lib = ctypes.CDLL(os.path.abspath(lib_path))
    print(" Bibliothèque chargée avec succès")
except OSError as e:
    print(f" Erreur de chargement : {e}")
    exit(1)

# Configuration des signatures
BUFFER_SIZE = 8192

rsa_lib.generate_rsa_keys.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
rsa_lib.generate_rsa_keys.restype = None

rsa_lib.rsa_encrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
rsa_lib.rsa_encrypt_string.restype = None

rsa_lib.rsa_decrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
rsa_lib.rsa_decrypt_string.restype = None

print(" Signatures configurées")

# Test 1 : Génération de clés
print("\n Test de génération de clés...")
try:
    n_out = ctypes.create_string_buffer(BUFFER_SIZE)
    d_out = ctypes.create_string_buffer(BUFFER_SIZE)
    
    print(" Génération en cours (peut prendre quelques minutes)...")
    rsa_lib.generate_rsa_keys(n_out, d_out, BUFFER_SIZE)
    
    n_val = n_out.value.decode('utf-8')
    d_val = d_out.value.decode('utf-8')
    e_val = '10001'
    
    print(f" Clés générées !")
    print(f"   N: {n_val[:50]}...")
    print(f"   E: {e_val}")
    print(f"   D: {d_val[:50]}...")
    
except Exception as e:
    print(f" Erreur génération clés : {e}")
    exit(1)

# Test 2 : Chiffrement simple
print("\n Test de chiffrement...")
try:
    message = "Test123"
    print(f"   Message original: '{message}'")
    
    encrypted_out = ctypes.create_string_buffer(BUFFER_SIZE)
    
    rsa_lib.rsa_encrypt_string(
        message.encode('utf-8'),
        e_val.encode('utf-8'),
        n_val.encode('utf-8'),
        encrypted_out,
        BUFFER_SIZE,
        6  # Utilise mpz_powm de GMP
    )
    
    encrypted_hex = encrypted_out.value.decode('utf-8')
    print(f" Chiffrement réussi: {encrypted_hex[:50]}...")
    
except Exception as e:
    print(f" Erreur chiffrement : {e}")
    exit(1)

# Test 3 : Déchiffrement
print("\n Test de déchiffrement...")
try:
    decrypted_out = ctypes.create_string_buffer(BUFFER_SIZE)
    
    rsa_lib.rsa_decrypt_string(
        encrypted_hex.encode('utf-8'),
        d_val.encode('utf-8'),
        n_val.encode('utf-8'),
        decrypted_out,
        BUFFER_SIZE,
        6  # Utilise mpz_powm de GMP
    )
    
    decrypted_message = decrypted_out.value.decode('utf-8')
    print(f"   Message déchiffré: '{decrypted_message}'")
    
    if decrypted_message == message:
        print(" Test complet réussi ! Le message original et déchiffré correspondent.")
    else:
        print(" Erreur: Les messages ne correspondent pas")
        print(f"   Original: '{message}'")
        print(f"   Déchiffré: '{decrypted_message}'")
        
except Exception as e:
    print(f" Erreur déchiffrement : {e}")
    exit(1)

print("\n Tous les tests sont passés avec succès !")