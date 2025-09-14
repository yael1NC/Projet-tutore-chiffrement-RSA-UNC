#!/usr/bin/env python3
"""
Outil de migration pour convertir les clés RSA non chiffrées 
vers le stockage sécurisé avec padding et chiffrement AES-256-GCM
"""

import os
import sys
import shutil
import getpass
from key_manager import SecureKeyManager

class RSAKeyMigrator:
    def __init__(self, key_dir="keys"):
        self.key_dir = key_dir
        self.key_manager = SecureKeyManager(key_dir)
        
        # Fichiers de clés originaux
        self.original_files = {
            'n': os.path.join(key_dir, "public_n.key"),
            'e': os.path.join(key_dir, "public_e.key"),
            'd': os.path.join(key_dir, "private_d.key")
        }
        
        # Dossier de sauvegarde
        self.backup_dir = os.path.join(key_dir, "backup_plaintext")
    
    def check_original_keys(self):
        """Vérifie la présence des clés originales"""
        print("Vérification des clés RSA existantes...")
        
        missing_files = []
        existing_files = []
        
        for key_type, file_path in self.original_files.items():
            if os.path.exists(file_path):
                existing_files.append((key_type, file_path))
                file_size = os.path.getsize(file_path)
                print(f"  Trouvé {key_type.upper()}: {os.path.basename(file_path)} ({file_size} bytes)")
            else:
                missing_files.append((key_type, file_path))
        
        if missing_files:
            print("Fichiers manquants:")
            for key_type, file_path in missing_files:
                print(f"  Manque {key_type.upper()}: {os.path.basename(file_path)}")
            return False
        
        print(f"Toutes les clés trouvées ({len(existing_files)} fichiers)")
        return True
    
    def load_original_keys(self):
        """Charge les clés depuis les fichiers originaux"""
        try:
            keys = {}
            
            for key_type, file_path in self.original_files.items():
                with open(file_path, 'r') as f:
                    content = f.read().strip()
                    keys[key_type] = content
                    print(f"Clé {key_type.upper()} chargée: {content[:50]}...")
            
            # Validation basique
            if not keys['n'] or not keys['e'] or not keys['d']:
                raise ValueError("Une ou plusieurs clés sont vides")
            
            # Vérifier que les clés sont en hexadécimal
            for key_type, value in keys.items():
                try:
                    int(value, 16)  # Test de conversion hexadécimale
                except ValueError:
                    raise ValueError(f"La clé {key_type.upper()} n'est pas en format hexadécimal valide")
            
            return keys['n'], keys['e'], keys['d']
            
        except Exception as e:
            print(f"Erreur lors du chargement des clés: {e}")
            return None, None, None
    
    def create_backup(self):
        """Crée une sauvegarde des fichiers originaux"""
        print("Création d'une sauvegarde des clés originales...")
        
        try:
            if os.path.exists(self.backup_dir):
                print(f"Dossier de sauvegarde existant: {self.backup_dir}")
                response = input("Écraser la sauvegarde existante ? (o/N): ").lower()
                if response != 'o':
                    print("Sauvegarde annulée")
                    return False
                shutil.rmtree(self.backup_dir)
            
            os.makedirs(self.backup_dir, mode=0o700)
            
            # Copier chaque fichier
            for key_type, file_path in self.original_files.items():
                if os.path.exists(file_path):
                    backup_path = os.path.join(self.backup_dir, os.path.basename(file_path))
                    shutil.copy2(file_path, backup_path)
                    # Définir des permissions restrictives
                    os.chmod(backup_path, 0o600)
                    print(f"  Sauvegardé: {os.path.basename(file_path)}")
            
            # Créer un fichier d'information
            info_file = os.path.join(self.backup_dir, "backup_info.txt")
            with open(info_file, 'w') as f:
                f.write("Sauvegarde des clés RSA en clair\n")
                f.write(f"Créée le: {__import__('time').ctime()}\n")
                f.write(f"Dossier original: {os.path.abspath(self.key_dir)}\n")
                f.write("\nATTENTION: Ces fichiers contiennent vos clés privées RSA en clair!\n")
                f.write("Supprimez cette sauvegarde une fois la migration vérifiée.\n")
            
            print(f"Sauvegarde créée dans: {self.backup_dir}")
            return True
            
        except Exception as e:
            print(f"Erreur lors de la sauvegarde: {e}")
            return False
    
    def migrate_to_secure_storage(self, n_val, e_val, d_val):
        """Migre les clés vers le stockage sécurisé"""
        print("Migration vers le stockage sécurisé...")
        
        print("Création d'un mot de passe pour protéger vos clés RSA.")
        print("Ce mot de passe sera nécessaire pour utiliser vos clés à l'avenir.")
        
        # Demander le mot de passe
        while True:
            password = getpass.getpass("Nouveau mot de passe: ")
            if len(password) < 8:
                print("Le mot de passe doit contenir au moins 8 caractères")
                continue
            
            confirm_password = getpass.getpass("Confirmez le mot de passe: ")
            if password != confirm_password:
                print("Les mots de passe ne correspondent pas")
                continue
            
            break
        
        # Chiffrer et sauvegarder
        if self.key_manager.encrypt_keys(n_val, e_val, d_val, password):
            print("Migration réussie vers le stockage sécurisé!")
            return True
        else:
            print("Échec de la migration")
            return False
    
    def verify_migration(self):
        """Vérifie que la migration a réussi"""
        print("Vérification de la migration...")
        
        if not self.key_manager.has_encrypted_keys():
            print("Erreur: Aucune clé chiffrée trouvée après migration")
            return False
        
        try:
            # Tester le déchiffrement
            password = getpass.getpass("Mot de passe pour vérification: ")
            n_val, e_val, d_val = self.key_manager.decrypt_keys(password)
            
            print("Vérification réussie!")
            print(f"  N: {n_val[:50]}...")
            print(f"  E: {e_val}")
            print(f"  D: {d_val[:50]}...")
            
            # Afficher les informations de sécurité
            self.key_manager.get_key_info()
            
            return True
            
        except Exception as e:
            print(f"Erreur lors de la vérification: {e}")
            return False
    
    def cleanup_original_files(self):
        """Supprime les fichiers de clés originaux"""
        print("Suppression sécurisée des fichiers de clés originaux...")
        
        confirm = input("Êtes-vous sûr de vouloir supprimer les clés en clair ? (o/N): ")
        if confirm.lower() != 'o':
            print("Suppression annulée - Les fichiers originaux sont conservés")
            return False
        
        try:
            for key_type, file_path in self.original_files.items():
                if os.path.exists(file_path):
                    # Écraser avec des données aléatoires
                    file_size = os.path.getsize(file_path)
                    with open(file_path, 'wb') as f:
                        f.write(__import__('secrets').token_bytes(file_size))
                    
                    # Supprimer le fichier
                    os.remove(file_path)
                    print(f"  Supprimé: {os.path.basename(file_path)}")
            
            print("Suppression terminée - Clés originales effacées")
            return True
            
        except Exception as e:
            print(f"Erreur lors de la suppression: {e}")
            return False
    
    def run_migration(self):
        """Lance le processus complet de migration"""
        print("=" * 60)
        print("  OUTIL DE MIGRATION RSA VERS STOCKAGE SÉCURISÉ")
        print("=" * 60)
        
        # Étape 1: Vérifier les clés existantes
        if not self.check_original_keys():
            print("Migration impossible - Clés manquantes")
            return False
        
        # Vérifier si une migration a déjà été effectuée
        if self.key_manager.has_encrypted_keys():
            print("Des clés chiffrées existent déjà!")
            response = input("Voulez-vous les écraser ? (o/N): ")
            if response.lower() != 'o':
                print("Migration annulée")
                return False
        
        # Étape 2: Charger les clés originales
        print("\nÉtape 1/5: Chargement des clés originales")
        n_val, e_val, d_val = self.load_original_keys()
        if not n_val:
            return False
        
        # Étape 3: Créer une sauvegarde
        print("\nÉtape 2/5: Sauvegarde des clés originales")
        if not self.create_backup():
            return False
        
        # Étape 4: Migration vers le stockage sécurisé
        print("\nÉtape 3/5: Migration vers le stockage sécurisé")
        if not self.migrate_to_secure_storage(n_val, e_val, d_val):
            print("Échec de la migration - Les fichiers originaux sont conservés")
            return False
        
        # Étape 5: Vérification
        print("\nÉtape 4/5: Vérification de la migration")
        if not self.verify_migration():
            print("Échec de la vérification - Les fichiers originaux sont conservés")
            return False
        
        # Étape 6: Nettoyage (optionnel)
        print("\nÉtape 5/5: Nettoyage des fichiers originaux")
        self.cleanup_original_files()
        
        print("\n" + "=" * 60)
        print("MIGRATION TERMINÉE AVEC SUCCÈS!")
        print("=" * 60)
        print("Vos clés RSA sont maintenant protégées par:")
        print("  - Chiffrement AES-256-GCM")
        print("  - Dérivation de clé PBKDF2-HMAC-SHA256 (100,000 itérations)")
        print("  - Padding PKCS7")
        print("  - Sel cryptographique aléatoire")
        print()
        print(f"Sauvegarde disponible dans: {self.backup_dir}")
        print("Supprimez la sauvegarde une fois que vous avez vérifié que tout fonctionne.")
        
        return True
    
    def restore_from_backup(self):
        """Restaure les clés depuis la sauvegarde"""
        print("Restauration depuis la sauvegarde...")
        
        if not os.path.exists(self.backup_dir):
            print("Aucune sauvegarde trouvée")
            return False
        
        try:
            for key_type, file_path in self.original_files.items():
                backup_path = os.path.join(self.backup_dir, os.path.basename(file_path))
                if os.path.exists(backup_path):
                    shutil.copy2(backup_path, file_path)
                    print(f"  Restauré: {os.path.basename(file_path)}")
            
            print("Restauration terminée")
            return True
            
        except Exception as e:
            print(f"Erreur lors de la restauration: {e}")
            return False


def main():
    """Fonction principale"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Migration des clés RSA vers le stockage sécurisé")
    parser.add_argument("--key-dir", default="keys", help="Dossier des clés (défaut: keys)")
    parser.add_argument("--restore", action="store_true", help="Restaurer depuis la sauvegarde")
    parser.add_argument("--info", action="store_true", help="Afficher les informations sur les clés")
    
    args = parser.parse_args()
    
    migrator = RSAKeyMigrator(args.key_dir)
    
    if args.restore:
        migrator.restore_from_backup()
    elif args.info:
        migrator.key_manager.get_key_info()
    else:
        migrator.run_migration()


if __name__ == "__main__":
    main()