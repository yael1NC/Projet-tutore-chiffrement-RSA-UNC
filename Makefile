CC = gcc
CFLAGS = -Wall -Wextra -fPIC -g -O0
LDFLAGS = -shared
LIBS = -lgmp -lsodium

# Fichiers
SRC = src/rsa.c
TARGET = rsa_lib.so

# Règle par défaut
all: $(TARGET)

# Compilation directe en .so
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o  $(TARGET) $(SRC) $(LIBS)

# Nettoyage
clean:
	rm -f $(TARGET)

# Reconstruction complète
rebuild: clean all

.PHONY: all clean rebuild