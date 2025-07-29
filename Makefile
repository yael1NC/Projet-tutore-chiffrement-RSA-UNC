# gcc -shared -o rsa_lib.so rsa.c -lgmp -lsodium -fPIC
# mkdir keys
# python3 rsa_server.py