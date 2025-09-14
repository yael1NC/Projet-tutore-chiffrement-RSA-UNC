#!/usr/bin/env python3
"""
Gestionnaire de clés RSA sécurisé avec padding et chiffrement
Utilise PBKDF2 + AES-256-GCM pour protéger les clés stockées
"""

import os
import json
import base64
import getpass
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

class SecureKeyManager:
    def __init__(self, key_dir="keys"):
        self.key_dir = key_dir
        self.encrypted_key_file = os.path.join(key_dir, "rsa_keys.enc")
        self.salt_file = os.path.join(key_dir, "key.salt")
        
        if not os.path.exists(key_dir):
            os.makedirs(key_dir, mode=0o700)  # Permissions restrictives
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Dérive une clé AES-256 à partir du mot de passe et du sel"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits pour AES-256
            salt=salt,
            iterations=100000,  # Nombre d'itérations élevé pour la sécurité
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _pad_data(self, data: str) -> str:
        """Ajoute un padding PKCS7 aux données avant chiffrement"""
        # Convertir en bytes pour le padding
        data_bytes = data.encode('utf-8')
        
        # PKCS7 padding pour AES (blocs de 16 bytes)
        block_size = 16
        padding_length = block_size - (len(data_bytes) % block_size)
        padding = bytes([padding_length] * padding_length)
        
        padded_data = data_bytes + padding
        return base64.b64encode(padded_data).decode('utf-8')
    
    def _unpad_data(self, padded_data: str) -> str:
        """Supprime le padding PKCS7 des données après déchiffrement"""
        try:
            # Décoder de base64
            data_bytes = base64.b64decode(padded_data.encode('utf-8'))
            
            # Supprimer le padding PKCS7
            padding_length = data_bytes[-1]
            
            # Vérification de la validité du padding
            if padding_length > 16 or padding_length == 0:
                raise ValueError("Padding invalide")
            
            # Vérifier que tous les bytes de padding sont identiques
            for i in range(padding_length):
                if data_bytes[-(i+1)] != padding_length:
                    raise ValueError("Padding PKCS7 invalide")
            
            unpadded_data = data_bytes[:-padding_length]
            return unpadded_data.decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"Erreur lors de la suppression du padding: {e}")
    
    def encrypt_keys(self, n_val: str, e_val: str, d_val: str, password: str = None) -> bool:
        """Chiffre et sauvegarde les clés RSA avec un mot de passe"""
        try:
            if password is None:
                password = getpass.getpass("Entrez un mot de passe pour protéger les clés RSA: ")
                confirm_password = getpass.getpass("Confirmez le mot de passe: ")
                
                if password != confirm_password:
                    print("Les mots de passe ne correspondent pas!")
                    return False
            
            # Générer un sel aléatoire
            salt = secrets.token_bytes(32)
            
            # Dériver la clé de chiffrement
            encryption_key = self._derive_key(password, salt)
            
            # Préparer les données à chiffrer avec padding
            key_data = {
                'n': self._pad_data(n_val),
                'e': self._pad_data(e_val),
                'd': self._pad_data(d_val),
                'created': os.path.getmtime(os.path.join(self.key_dir, "public_n.key")) if os.path.exists(os.path.join(self.key_dir, "public_n.key")) else None,
                'key_size': 4096,
                'algorithm': 'RSA',
                'padding': 'PKCS7'
            }
            
            # Convertir en JSON puis en bytes
            json_data = json.dumps(key_data, indent=2).encode('utf-8')
            
            # Générer un IV aléatoire pour AES-GCM
            iv = secrets.token_bytes(12)  # 96 bits pour GCM
            
            # Chiffrer avec AES-256-GCM
            cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            ciphertext = encryptor.update(json_data) + encryptor.finalize()
            
            # Préparer les données chiffrées
            encrypted_data = {
                'version': '1.0',
                'cipher': 'AES-256-GCM',
                'kdf': 'PBKDF2-HMAC-SHA256',
                'iterations': 100000,
                'iv': base64.b64encode(iv).decode('utf-8'),
                'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
                'data': base64.b64encode(ciphertext).decode('utf-8')
            }
            
            # Sauvegarder le sel
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            os.chmod(self.salt_file, 0o600)  # Lecture/écriture pour le propriétaire seulement
            
            # Sauvegarder les données chiffrées
            with open(self.encrypted_key_file, 'w') as f:
                json.dump(encrypted_data, f, indent=2)
            os.chmod(self.encrypted_key_file, 0o600)
            
            print("✅ Clés RSA chiffrées et sauvegardées avec succès")
            print(f"📁 Fichier chiffré: {self.encrypted_key_file}")
            print(f"🔑 Fichier sel: {self.salt_file}")
            
            # Supprimer les clés en clair (optionnel)
            self._cleanup_plaintext_keys()
            
            return True
            
        except Exception as e:
            print(f"❌ Erreur lors du chiffrement des clés: {e}")
            return False
    
    def decrypt_keys(self, password: str = None) -> tuple:
        """Déchiffre et retourne les clés RSA"""
        try:
            if not os.path.exists(self.encrypted_key_file) or not os.path.exists(self.salt_file):
                raise FileNotFoundError("Fichiers de clés chiffrées introuvables")
            
            if password is None:
                password = getpass.getpass("Entrez le mot de passe des clés RSA: ")
            
            # Charger le sel
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
            
            # Dériver la clé de déchiffrement
            decryption_key = self._derive_key(password, salt)
            
            # Charger les données chiffrées
            with open(self.encrypted_key_file, 'r') as f:
                encrypted_data = json.load(f)
            
            # Vérifier la version
            if encrypted_data.get('version') != '1.0':
                raise ValueError("Version de fichier non supportée")
            
            # Extraire les composants
            iv = base64.b64decode(encrypted_data['iv'])
            tag = base64.b64decode(encrypted_data['tag'])
            ciphertext = base64.b64decode(encrypted_data['data'])
            
            # Déchiffrer avec AES-256-GCM
            cipher = Cipher(algorithms.AES(decryption_key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Parser les données JSON
            key_data = json.loads(decrypted_data.decode('utf-8'))
            
            # Supprimer le padding et retourner les clés
            n_val = self._unpad_data(key_data['n'])
            e_val = self._unpad_data(key_data['e'])
            d_val = self._unpad_data(key_data['d'])
            
            print("✅ Clés RSA déchiffrées avec succès")
            return n_val, e_val, d_val
            
        except Exception as e:
            print(f"❌ Erreur lors du déchiffrement: {e}")
            raise
    
    def _cleanup_plaintext_keys(self):
        """Supprime les clés en clair (optionnel)"""
        plaintext_files = [
            os.path.join(self.key_dir, "public_n.key"),
            os.path.join(self.key_dir, "public_e.key"),
            os.path.join(self.key_dir, "private_d.key")
        ]
        
        for file_path in plaintext_files:
            if os.path.exists(file_path):
                try:
                    # Écraser le fichier avec des données aléatoires avant suppression
                    file_size = os.path.getsize(file_path)
                    with open(file_path, 'wb') as f:
                        f.write(secrets.token_bytes(file_size))
                    os.remove(file_path)
                    print(f"🗑️  Fichier en clair supprimé: {os.path.basename(file_path)}")
                except Exception as e:
                    print(f"⚠️  Impossible de supprimer {file_path}: {e}")
    
    def has_encrypted_keys(self) -> bool:
        """Vérifie si des clés chiffrées existent"""
        return (os.path.exists(self.encrypted_key_file) and 
                os.path.exists(self.salt_file))
    
    def change_password(self, old_password: str = None, new_password: str = None):
        """Change le mot de passe de protection des clés"""
        try:
            if not self.has_encrypted_keys():
                print("❌ Aucune clé chiffrée trouvée")
                return False
            
            # Déchiffrer avec l'ancien mot de passe
            if old_password is None:
                old_password = getpass.getpass("Ancien mot de passe: ")
            
            n_val, e_val, d_val = self.decrypt_keys(old_password)
            
            # Chiffrer avec le nouveau mot de passe
            if new_password is None:
                new_password = getpass.getpass("Nouveau mot de passe: ")
            
            success = self.encrypt_keys(n_val, e_val, d_val, new_password)
            
            if success:
                print("✅ Mot de passe changé avec succès")
            
            return success
            
        except Exception as e:
            print(f"❌ Erreur lors du changement de mot de passe: {e}")
            return False
    
    def export_public_key(self, output_file: str = None, password: str = None):
        """Exporte la clé publique (N, E) vers un fichier non chiffré"""
        try:
            n_val, e_val, d_val = self.decrypt_keys(password)
            
            if output_file is None:
                output_file = os.path.join(self.key_dir, "rsa_public.key")
            
            public_key_data = {
                'n': n_val,
                'e': e_val,
                'key_size': 4096,
                'algorithm': 'RSA',
                'type': 'public'
            }
            
            with open(output_file, 'w') as f:
                json.dump(public_key_data, f, indent=2)
            
            print(f"✅ Clé publique exportée vers: {output_file}")
            return True
            
        except Exception as e:
            print(f"❌ Erreur lors de l'export: {e}")
            return False
    
    def get_key_info(self):
        """Affiche les informations sur les clés sans les déchiffrer"""
        try:
            if not self.has_encrypted_keys():
                print("❌ Aucune clé chiffrée trouvée")
                return
            
            with open(self.encrypted_key_file, 'r') as f:
                encrypted_data = json.load(f)
            
            print("\n📋 Informations sur les clés chiffrées:")
            print("="*50)
            print(f"Version: {encrypted_data.get('version', 'Inconnue')}")
            print(f"Algorithme de chiffrement: {encrypted_data.get('cipher', 'Inconnu')}")
            print(f"Fonction de dérivation de clé: {encrypted_data.get('kdf', 'Inconnue')}")
            print(f"Nombre d'itérations: {encrypted_data.get('iterations', 'Inconnu')}")
            
            # Informations sur les fichiers
            enc_stat = os.stat(self.encrypted_key_file)
            salt_stat = os.stat(self.salt_file)
            
            print(f"Taille fichier chiffré: {enc_stat.st_size} bytes")
            print(f"Taille fichier sel: {salt_stat.st_size} bytes")
            print(f"Permissions fichier chiffré: {oct(enc_stat.st_mode)[-3:]}")
            print(f"Permissions fichier sel: {oct(salt_stat.st_mode)[-3:]}")
            
        except Exception as e:
            print(f"❌ Erreur lors de la lecture des informations: {e}")


def main():
    """Fonction de test et démonstration"""
    print("🔐 Gestionnaire de clés RSA sécurisé")
    print("="*40)
    
    key_manager = SecureKeyManager()
    
    # Exemple d'utilisation
    if key_manager.has_encrypted_keys():
        print("📋 Clés chiffrées détectées")
        key_manager.get_key_info()
        
        try:
            n, e, d = key_manager.decrypt_keys()
            print(f"📄 Clé publique N: {n[:50]}...")
            print(f"📄 Clé publique E: {e}")
            print(f"🔐 Clé privée D: {d[:50]}...")
        except:
            print("❌ Impossible de déchiffrer les clés")
    else:
        print("📋 Aucune clé chiffrée trouvée")
        print("Utilisez ce gestionnaire avec vos clés RSA existantes")


if __name__ == "__main__":
    main()