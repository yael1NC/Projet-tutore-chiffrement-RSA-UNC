#!/usr/bin/env python3
"""
Interface principale pour le système de chiffrement RSA
Permet de choisir l'algorithme d'exponentiation modulaire
"""

import ctypes
import os
import time
import json

# Configuration
BUFFER_SIZE = 8192
KEY_DIR = "keys"
PUB_N_FILE = os.path.join(KEY_DIR, "public_n.key")
PUB_E_FILE = os.path.join(KEY_DIR, "public_e.key")
PRIV_D_FILE = os.path.join(KEY_DIR, "private_d.key")

# Algorithmes disponibles
ALGORITHMS = {
    1: "Square and Multiply (Basique)",
    2: "Square and Multiply Always (Résistant aux attaques par canal auxiliaire)",
    3: "Montgomery Ladder (Équilibré)",
    4: "Semi-interleaved Ladder (Sécurisé)",
    5: "Fully-interleaved Ladder (Très sécurisé)",
    6: "GMP mpz_powm (Optimisé par défaut)"
}

class RSAInterface:
    def __init__(self):
        self.rsa_lib = None
        self.n_val = None
        self.e_val = None
        self.d_val = None
        self.load_library()
    
    def load_library(self):
        """Charge la bibliothèque C RSA"""
        try:
            lib_path = os.path.join(os.path.dirname(__file__), '..', 'rsa_lib.so')
            self.rsa_lib = ctypes.CDLL(os.path.abspath(lib_path))
            
            # Configuration des signatures
            self.rsa_lib.generate_rsa_keys.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
            self.rsa_lib.generate_rsa_keys.restype = None
            
            self.rsa_lib.rsa_encrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
            self.rsa_lib.rsa_encrypt_string.restype = None
            
            self.rsa_lib.rsa_decrypt_string.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
            self.rsa_lib.rsa_decrypt_string.restype = None
            
            print("✅ Bibliothèque RSA chargée avec succès")
            
        except OSError as e:
            print(f"❌ Erreur : Impossible de charger la bibliothèque rsa_lib.so")
            print(f"   Détails : {e}")
            print("   Assurez-vous que la bibliothèque est compilée dans le répertoire parent.")
            exit(1)
    
    def load_or_generate_keys(self):
        """Charge les clés existantes ou en génère de nouvelles"""
        print("\n🔑 Gestion des clés RSA...")
        
        if (os.path.exists(PUB_N_FILE) and 
            os.path.exists(PUB_E_FILE) and 
            os.path.exists(PRIV_D_FILE)):
            
            print("📁 Clés existantes trouvées, chargement...")
            with open(PUB_N_FILE, 'r') as f:
                self.n_val = f.read().strip()
            with open(PUB_E_FILE, 'r') as f:
                self.e_val = f.read().strip()
            with open(PRIV_D_FILE, 'r') as f:
                self.d_val = f.read().strip()
                
            print("✅ Clés chargées avec succès")
            print(f"   N: {self.n_val[:50]}...")
            print(f"   E: {self.e_val}")
            return
        
        print("🔧 Génération de nouvelles clés RSA (4096 bits)...")
        print("⚠️  Cela peut prendre quelques minutes...")
        
        if not os.path.exists(KEY_DIR):
            os.makedirs(KEY_DIR)
        
        n_out = ctypes.create_string_buffer(BUFFER_SIZE)
        d_out = ctypes.create_string_buffer(BUFFER_SIZE)
        
        start_time = time.time()
        self.rsa_lib.generate_rsa_keys(n_out, d_out, BUFFER_SIZE)
        generation_time = time.time() - start_time
        
        self.n_val = n_out.value.decode('utf-8')
        self.d_val = d_out.value.decode('utf-8')
        self.e_val = '10001'  # Exposant public standard
        
        # Sauvegarde
        with open(PUB_N_FILE, 'w') as f:
            f.write(self.n_val)
        with open(PUB_E_FILE, 'w') as f:
            f.write(self.e_val)
        with open(PRIV_D_FILE, 'w') as f:
            f.write(self.d_val)
        
        print(f"✅ Clés générées en {generation_time:.2f} secondes")
        print(f"   N: {self.n_val[:50]}...")
        print(f"   E: {self.e_val}")
        print("💾 Clés sauvegardées dans le dossier 'keys/'")
    
    def encrypt_message(self, message, algo_choice):
        """Chiffre un message avec l'algorithme choisi"""
        encrypted_out = ctypes.create_string_buffer(BUFFER_SIZE)
        
        start_time = time.time()
        self.rsa_lib.rsa_encrypt_string(
            message.encode('utf-8'),
            self.e_val.encode('utf-8'),
            self.n_val.encode('utf-8'),
            encrypted_out,
            BUFFER_SIZE,
            algo_choice
        )
        encryption_time = time.time() - start_time
        
        return encrypted_out.value.decode('utf-8'), encryption_time
    
    def decrypt_message(self, encrypted_hex, algo_choice):
        """Déchiffre un message avec l'algorithme choisi"""
        decrypted_out = ctypes.create_string_buffer(BUFFER_SIZE)
        
        start_time = time.time()
        self.rsa_lib.rsa_decrypt_string(
            encrypted_hex.encode('utf-8'),
            self.d_val.encode('utf-8'),
            self.n_val.encode('utf-8'),
            decrypted_out,
            BUFFER_SIZE,
            algo_choice
        )
        decryption_time = time.time() - start_time
        
        return decrypted_out.value.decode('utf-8'), decryption_time
    
    def display_algorithms(self):
        """Affiche la liste des algorithmes disponibles"""
        print("\n📋 Algorithmes d'exponentiation modulaire disponibles :")
        print("=" * 70)
        for num, desc in ALGORITHMS.items():
            print(f"   {num}. {desc}")
        print("=" * 70)
    
    def get_algorithm_choice(self):
        """Demande à l'utilisateur de choisir un algorithme"""
        while True:
            try:
                choice = int(input(f"\n🔢 Choisissez un algorithme (1-{len(ALGORITHMS)}) : "))
                if choice in ALGORITHMS:
                    return choice
                else:
                    print(f"❌ Veuillez choisir un nombre entre 1 et {len(ALGORITHMS)}")
            except ValueError:
                print("❌ Veuillez entrer un nombre valide")
    
    def benchmark_algorithms(self, message="Test de performance"):
        """Compare les performances de tous les algorithmes"""
        print(f"\n⏱️  Benchmark des algorithmes avec le message : '{message}'")
        print("=" * 80)
        
        results = []
        
        for algo_num, algo_name in ALGORITHMS.items():
            print(f"\n🔄 Test de l'algorithme {algo_num}: {algo_name}")
            
            try:
                # Test de chiffrement
                encrypted_hex, enc_time = self.encrypt_message(message, algo_num)
                
                # Test de déchiffrement
                decrypted_message, dec_time = self.decrypt_message(encrypted_hex, algo_num)
                
                # Vérification
                if decrypted_message == message:
                    status = "✅ Succès"
                    total_time = enc_time + dec_time
                    results.append({
                        'algorithm': algo_name,
                        'encryption_time': enc_time,
                        'decryption_time': dec_time,
                        'total_time': total_time,
                        'status': 'Succès'
                    })
                    print(f"   Chiffrement: {enc_time:.4f}s | Déchiffrement: {dec_time:.4f}s | Total: {total_time:.4f}s")
                else:
                    status = "❌ Échec"
                    results.append({
                        'algorithm': algo_name,
                        'status': 'Échec'
                    })
                    print(f"   {status} - Message déchiffré incorrect")
                
            except Exception as e:
                print(f"   ❌ Erreur : {e}")
                results.append({
                    'algorithm': algo_name,
                    'status': f'Erreur: {e}'
                })
        
        # Affichage du résumé
        self.display_benchmark_results(results)
        return results
    
    def display_benchmark_results(self, results):
        """Affiche un résumé des résultats de benchmark"""
        print("\n📊 Résumé des performances :")
        print("=" * 80)
        
        successful_results = [r for r in results if r['status'] == 'Succès']
        
        if successful_results:
            # Tri par temps total
            successful_results.sort(key=lambda x: x['total_time'])
            
            print(f"{'Rang':<4} {'Algorithme':<45} {'Chiffrement':<12} {'Déchiffrement':<15} {'Total':<10}")
            print("-" * 80)
            
            for i, result in enumerate(successful_results, 1):
                print(f"{i:<4} {result['algorithm']:<45} "
                      f"{result['encryption_time']:.4f}s{'':<4} "
                      f"{result['decryption_time']:.4f}s{'':<6} "
                      f"{result['total_time']:.4f}s")
            
            fastest = successful_results[0]
            print(f"\n🏆 Algorithme le plus rapide : {fastest['algorithm']}")
            print(f"   Temps total : {fastest['total_time']:.4f} secondes")
        
        # Affichage des échecs
        failed_results = [r for r in results if r['status'] != 'Succès']
        if failed_results:
            print(f"\n❌ Algorithmes avec des erreurs :")
            for result in failed_results:
                print(f"   • {result['algorithm']} : {result['status']}")
    
    def interactive_mode(self):
        """Mode interactif principal"""
        print("🎯 Mode interactif - Chiffrement/Déchiffrement RSA")
        
        while True:
            print("\n" + "="*60)
            print("🔐 MENU PRINCIPAL")
            print("="*60)
            print("1. 📝 Chiffrer un message")
            print("2. 🔓 Déchiffrer un message")
            print("3. 🔄 Chiffrer puis déchiffrer (test complet)")
            print("4. ⏱️  Benchmark des algorithmes")
            print("5. 📋 Afficher les algorithmes disponibles")
            print("6. 🔑 Régénérer les clés RSA")
            print("7. ❌ Quitter")
            print("="*60)
            
            try:
                choice = input("Votre choix : ").strip()
                
                if choice == '1':
                    self.encrypt_mode()
                elif choice == '2':
                    self.decrypt_mode()
                elif choice == '3':
                    self.test_complete_mode()
                elif choice == '4':
                    message = input("\n📝 Message pour le benchmark (ou Entrée pour 'Test de performance') : ").strip()
                    if not message:
                        message = "Test de performance"
                    self.benchmark_algorithms(message)
                elif choice == '5':
                    self.display_algorithms()
                elif choice == '6':
                    self.regenerate_keys()
                elif choice == '7':
                    print("\n👋 Au revoir !")
                    break
                else:
                    print("❌ Choix invalide, veuillez réessayer")
                    
            except KeyboardInterrupt:
                print("\n\n👋 Au revoir !")
                break
            except Exception as e:
                print(f"❌ Erreur : {e}")
    
    def encrypt_mode(self):
        """Mode chiffrement"""
        message = input("\n📝 Entrez le message à chiffrer : ")
        if not message:
            print("❌ Message vide !")
            return
        
        self.display_algorithms()
        algo_choice = self.get_algorithm_choice()
        
        try:
            print(f"\n🔒 Chiffrement avec : {ALGORITHMS[algo_choice]}")
            encrypted_hex, enc_time = self.encrypt_message(message, algo_choice)
            
            print(f"✅ Message chiffré en {enc_time:.4f} secondes")
            print(f"📄 Message original : '{message}'")
            print(f"🔐 Message chiffré (hex) : {encrypted_hex}")
            
            # Sauvegarde optionnelle
            save = input("\n💾 Sauvegarder le message chiffré ? (o/N) : ").lower()
            if save == 'o':
                filename = f"encrypted_message_{int(time.time())}.txt"
                with open(filename, 'w') as f:
                    json.dump({
                        'original_message': message,
                        'encrypted_hex': encrypted_hex,
                        'algorithm_used': algo_choice,
                        'algorithm_name': ALGORITHMS[algo_choice],
                        'timestamp': time.time()
                    }, f, indent=2)
                print(f"💾 Message sauvegardé dans {filename}")
                
        except Exception as e:
            print(f"❌ Erreur lors du chiffrement : {e}")
    
    def decrypt_mode(self):
        """Mode déchiffrement"""
        encrypted_hex = input("\n🔐 Entrez le message chiffré (en hexadécimal) : ").strip()
        if not encrypted_hex:
            print("❌ Message vide !")
            return
        
        self.display_algorithms()
        algo_choice = self.get_algorithm_choice()
        
        try:
            print(f"\n🔓 Déchiffrement avec : {ALGORITHMS[algo_choice]}")
            decrypted_message, dec_time = self.decrypt_message(encrypted_hex, algo_choice)
            
            print(f"✅ Message déchiffré en {dec_time:.4f} secondes")
            print(f"🔐 Message chiffré : {encrypted_hex[:50]}...")
            print(f"📄 Message déchiffré : '{decrypted_message}'")
            
        except Exception as e:
            print(f"❌ Erreur lors du déchiffrement : {e}")
    
    def test_complete_mode(self):
        """Mode test complet (chiffrement + déchiffrement)"""
        message = input("\n📝 Entrez le message à tester : ")
        if not message:
            print("❌ Message vide !")
            return
        
        self.display_algorithms()
        algo_choice = self.get_algorithm_choice()
        
        try:
            print(f"\n🔄 Test complet avec : {ALGORITHMS[algo_choice]}")
            
            # Chiffrement
            print("🔒 Étape 1/2 : Chiffrement...")
            encrypted_hex, enc_time = self.encrypt_message(message, algo_choice)
            
            # Déchiffrement
            print("🔓 Étape 2/2 : Déchiffrement...")
            decrypted_message, dec_time = self.decrypt_message(encrypted_hex, algo_choice)
            
            # Résultats
            total_time = enc_time + dec_time
            print(f"\n📊 Résultats du test :")
            print(f"   📄 Message original    : '{message}'")
            print(f"   🔐 Message chiffré     : {encrypted_hex[:50]}...")
            print(f"   📄 Message déchiffré   : '{decrypted_message}'")
            print(f"   ⏱️  Temps chiffrement  : {enc_time:.4f}s")
            print(f"   ⏱️  Temps déchiffrement: {dec_time:.4f}s")
            print(f"   ⏱️  Temps total        : {total_time:.4f}s")
            
            if decrypted_message == message:
                print("   ✅ Test réussi : Les messages correspondent !")
            else:
                print("   ❌ Test échoué : Les messages ne correspondent pas !")
                
        except Exception as e:
            print(f"❌ Erreur lors du test : {e}")
    
    def regenerate_keys(self):
        """Régénère les clés RSA"""
        confirm = input("\n⚠️  Êtes-vous sûr de vouloir régénérer les clés ? (o/N) : ").lower()
        if confirm == 'o':
            # Suppression des anciennes clés
            for key_file in [PUB_N_FILE, PUB_E_FILE, PRIV_D_FILE]:
                if os.path.exists(key_file):
                    os.remove(key_file)
            
            print("🔧 Régénération des clés en cours...")
            self.load_or_generate_keys()
        else:
            print("❌ Régénération annulée")

def main():
    """Fonction principale"""
    print("🔐" + "="*58 + "🔐")
    print("  🎯 INTERFACE RSA - ALGORITHMES D'EXPONENTIATION MODULAIRE")
    print("🔐" + "="*58 + "🔐")
    
    try:
        rsa_interface = RSAInterface()
        rsa_interface.load_or_generate_keys()
        rsa_interface.interactive_mode()
        
    except KeyboardInterrupt:
        print("\n\n👋 Programme interrompu par l'utilisateur")
    except Exception as e:
        print(f"\n❌ Erreur fatale : {e}")

if __name__ == "__main__":
    main()