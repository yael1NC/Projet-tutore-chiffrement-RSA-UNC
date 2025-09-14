#!/usr/bin/env python3
"""
Script d'installation et de configuration pour le système RSA sécurisé
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

class SecureRSAInstaller:
    def __init__(self):
        self.project_root = Path.cwd()
        self.requirements_secure = [
            'cryptography>=3.0.0'
        ]
        self.required_files = [
            'rsa.h',
            'rsa.c'
        ]
    
    def check_python_version(self):
        """Vérifie la version de Python"""
        print("Vérification de la version Python...")
        
        if sys.version_info < (3, 6):
            print("❌ Python 3.6+ requis")
            print(f"Version actuelle: {sys.version}")
            return False
        
        print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}")
        return True
    
    def check_required_files(self):
        """Vérifie la présence des fichiers requis"""
        print("Vérification des fichiers source...")
        
        # Chercher dans plusieurs emplacements possibles
        search_paths = [
            self.project_root,  # Répertoire courant
            self.project_root.parent,  # Répertoire parent
            self.project_root / 'source',  # Sous-dossier source
            self.project_root.parent / 'source',  # source dans parent
            self.project_root / '..' / 'source',  # ../source
            self.project_root / 'src',  # Sous-dossier src
            self.project_root.parent / 'src',  # src dans parent
        ]
        
        found_files = {}
        missing_files = []
        
        for file_name in self.required_files:
            found = False
            for search_path in search_paths:
                file_path = Path(search_path) / file_name
                if file_path.exists():
                    found_files[file_name] = file_path.resolve()
                    print(f"✅ Trouvé {file_name}: {file_path}")
                    found = True
                    break
            
            if not found:
                missing_files.append(file_name)
        
        if missing_files:
            print("❌ Fichiers manquants:")
            for file_name in missing_files:
                print(f"   - {file_name}")
            print("\nCherché dans:")
            for path in search_paths:
                abs_path = Path(path).resolve()
                exists = "✓" if abs_path.exists() else "✗"
                print(f"   {exists} {abs_path}")
            return False
        
        # Copier les fichiers dans le répertoire courant s'ils ne s'y trouvent pas
        for file_name, file_path in found_files.items():
            local_path = self.project_root / file_name
            if not local_path.exists():
                print(f"Copie de {file_name} vers le répertoire courant...")
                shutil.copy2(file_path, local_path)
        
        print("✅ Tous les fichiers source disponibles")
        return True
    
    def check_system_dependencies(self):
        """Vérifie les dépendances système"""
        print("Vérification des dépendances système...")
        
        # Vérifier GCC
        try:
            result = subprocess.run(['gcc', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ GCC disponible")
            else:
                print("❌ GCC non trouvé")
                return False
        except FileNotFoundError:
            print("❌ GCC non installé")
            print("Sur Ubuntu/Debian: sudo apt-get install build-essential")
            print("Sur CentOS/RHEL: sudo yum install gcc")
            return False
        
        # Vérifier GMP
        test_code = '''
#include <gmp.h>
int main() { mpz_t x; mpz_init(x); mpz_clear(x); return 0; }
'''
        
        try:
            with open('test_gmp.c', 'w') as f:
                f.write(test_code)
            
            result = subprocess.run(['gcc', 'test_gmp.c', '-lgmp', '-o', 'test_gmp'], 
                                  capture_output=True, text=True)
            
            os.remove('test_gmp.c')
            if os.path.exists('test_gmp'):
                os.remove('test_gmp')
            
            if result.returncode == 0:
                print("✅ libgmp disponible")
            else:
                print("❌ libgmp non trouvée")
                print("Sur Ubuntu/Debian: sudo apt-get install libgmp-dev")
                print("Sur CentOS/RHEL: sudo yum install gmp-devel")
                return False
        except Exception as e:
            print(f"❌ Erreur lors du test GMP: {e}")
            return False
        
        # Vérifier Sodium
        test_sodium = '''
#include <sodium.h>
int main() { if (sodium_init() < 0) return 1; return 0; }
'''
        
        try:
            with open('test_sodium.c', 'w') as f:
                f.write(test_sodium)
            
            result = subprocess.run(['gcc', 'test_sodium.c', '-lsodium', '-o', 'test_sodium'], 
                                  capture_output=True, text=True)
            
            os.remove('test_sodium.c')
            if os.path.exists('test_sodium'):
                os.remove('test_sodium')
            
            if result.returncode == 0:
                print("✅ libsodium disponible")
            else:
                print("❌ libsodium non trouvée")
                print("Sur Ubuntu/Debian: sudo apt-get install libsodium-dev")
                print("Sur CentOS/RHEL: sudo yum install libsodium-devel")
                return False
        except Exception as e:
            print(f"❌ Erreur lors du test Sodium: {e}")
            return False
        
        return True
    
    def install_python_dependencies(self):
        """Installe les dépendances Python"""
        print("Installation des dépendances Python...")
        
        for package in self.requirements_secure:
            try:
                print(f"Installation de {package}...")
                result = subprocess.run([sys.executable, '-m', 'pip', 'install', package], 
                                      capture_output=True, text=True)
                
                if result.returncode == 0:
                    print(f"✅ {package} installé")
                else:
                    print(f"❌ Échec installation {package}")
                    print(result.stderr)
                    return False
            except Exception as e:
                print(f"❌ Erreur installation {package}: {e}")
                return False
        
        return True
    
    def compile_library(self):
        """Compile la bibliothèque RSA"""
        print("Compilation de la bibliothèque RSA...")
        
        compile_cmd = ['gcc', '-shared', '-fPIC', '-o', 'rsa_lib.so', 'rsa.c', '-lgmp', '-lsodium']
        
        try:
            result = subprocess.run(compile_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Bibliothèque RSA compilée (rsa_lib.so)")
                
                # Vérifier que le fichier existe et a les bonnes permissions
                lib_path = Path('rsa_lib.so')
                if lib_path.exists():
                    lib_path.chmod(0o755)
                    print(f"   Taille: {lib_path.stat().st_size} bytes")
                    return True
                else:
                    print("❌ Fichier rsa_lib.so non trouvé après compilation")
                    return False
            else:
                print("❌ Erreur de compilation")
                print("STDOUT:", result.stdout)
                print("STDERR:", result.stderr)
                return False
                
        except Exception as e:
            print(f"❌ Erreur lors de la compilation: {e}")
            return False
    
    def create_directory_structure(self):
        """Crée la structure des dossiers"""
        print("Création de la structure des dossiers...")
        
        directories = ['keys', 'client_keys', 'logs']
        
        for dir_name in directories:
            dir_path = Path(dir_name)
            if not dir_path.exists():
                dir_path.mkdir(mode=0o700)
                print(f"✅ Dossier créé: {dir_name}/")
            else:
                print(f"📁 Dossier existant: {dir_name}/")
        
        return True
    
    def create_config_file(self):
        """Crée un fichier de configuration"""
        print("Création du fichier de configuration...")
        
        config_content = '''# Configuration RSA Sécurisé
# Ce fichier contient les paramètres par défaut du système

[server]
host = 0.0.0.0
port = 65432
key_dir = keys

[client]
server_host = 127.0.0.1
server_port = 65432
key_cache_dir = client_keys

[security]
# Algorithme de chiffrement des clés
cipher = AES-256-GCM
kdf = PBKDF2-HMAC-SHA256
kdf_iterations = 100000

# Algorithme RSA par défaut (1-6)
default_rsa_algorithm = 6

[logging]
level = INFO
file = logs/rsa_secure.log
'''
        
        config_path = Path('config.ini')
        if not config_path.exists():
            with open(config_path, 'w') as f:
                f.write(config_content)
            print("✅ Fichier de configuration créé: config.ini")
        else:
            print("📄 Fichier de configuration existant")
        
        return True
    
    def run_tests(self):
        """Exécute des tests basiques"""
        print("Exécution des tests de base...")
        
        try:
            # Test d'import des modules
            print("Test d'import des modules...")
            
            import ctypes
            lib = ctypes.CDLL('./rsa_lib.so')
            print("✅ Bibliothèque C chargeable")
            
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            print("✅ Module cryptography fonctionnel")
            
            # Test de génération de clés (rapide)
            print("Test de génération de clés...")
            buffer_size = 8192
            
            lib.generate_rsa_keys.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
            lib.generate_rsa_keys.restype = None
            
            n_out = ctypes.create_string_buffer(buffer_size)
            d_out = ctypes.create_string_buffer(buffer_size)
            
            # Note: Le test complet prendrait trop de temps
            print("⚠️  Test de génération différé (trop long pour l'installation)")
            
            print("✅ Tests de base réussis")
            return True
            
        except Exception as e:
            print(f"❌ Échec des tests: {e}")
            return False
    
    def show_next_steps(self):
        """Affiche les étapes suivantes"""
        print("\n" + "="*60)
        print("  INSTALLATION TERMINÉE AVEC SUCCÈS!")
        print("="*60)
        
        print("\nPROCHAINES ÉTAPES:")
        print("-" * 20)
        
        if Path('keys/public_n.key').exists():
            print("1. Migrer vos clés existantes vers le stockage sécurisé:")
            print("   python migration_tool.py")
        else:
            print("1. Générer de nouvelles clés RSA:")
            print("   python rsa_server_secure.py")
            print("   (Des clés seront générées automatiquement)")
        
        print("\n2. Tester le système:")
        print("   # Terminal 1: Démarrer le serveur")
        print("   python rsa_server_secure.py")
        print("   ")
        print("   # Terminal 2: Tester le client")
        print("   python client_secure.py")
        
        print("\n3. Gestion des clés:")
        print("   python rsa_server_secure.py --manage-keys")
        
        print("\nFICHIERS IMPORTANTS:")
        print("- README_SECURE.md : Documentation complète")
        print("- config.ini : Configuration système")
        print("- keys/ : Dossier des clés sécurisées")
        print("- logs/ : Journaux du système")
        
        print("\nCOMMANDES UTILES:")
        print("- Migration: python migration_tool.py")
        print("- Serveur: python rsa_server_secure.py")
        print("- Client: python client_secure.py")
        print("- Interface originale: python main.py")
    
    def run_installation(self):
        """Exécute l'installation complète"""
        print("="*60)
        print("  INSTALLATION DU SYSTÈME RSA SÉCURISÉ")
        print("="*60)
        
        steps = [
            ("Vérification Python", self.check_python_version),
            ("Vérification des fichiers", self.check_required_files),
            ("Vérification des dépendances système", self.check_system_dependencies),
            ("Installation des dépendances Python", self.install_python_dependencies),
            ("Compilation de la bibliothèque", self.compile_library),
            ("Création des dossiers", self.create_directory_structure),
            ("Création de la configuration", self.create_config_file),
            ("Tests de base", self.run_tests)
        ]
        
        for i, (step_name, step_func) in enumerate(steps, 1):
            print(f"\nÉtape {i}/{len(steps)}: {step_name}")
            print("-" * 40)
            
            if not step_func():
                print(f"\n❌ ÉCHEC À L'ÉTAPE: {step_name}")
                print("Installation interrompue.")
                return False
        
        self.show_next_steps()
        return True


def main():
    """Fonction principale"""
    installer = SecureRSAInstaller()
    
    if len(sys.argv) > 1 and sys.argv[1] == '--check':
        # Mode vérification uniquement
        print("Mode vérification des dépendances...")
        installer.check_python_version()
        installer.check_required_files()
        installer.check_system_dependencies()
    else:
        # Installation complète
        success = installer.run_installation()
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()