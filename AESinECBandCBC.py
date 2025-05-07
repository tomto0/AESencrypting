import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tabulate import tabulate

# === Hilfsfunktionen für Padding ===
def pad(data, block_size=16):
    # Berechnet die Anzahl der fehlenden Bytes bis zur nächsten Blockgrenze
    padding_len = block_size - (len(data) % block_size)
    # Fügt Padding-Bytes hinzu, jeder mit dem Wert der Padding-Länge (PKCS#7-ähnlich)
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    # Liest die Padding-Länge aus dem letzten Byte
    padding_len = data[-1]
    # Entfernt die Padding-Bytes vom Ende
    return data[:-padding_len]

# === Eigene AES-Implementierungen (ECB/CBC) ===
def aes_ecb_encrypt(key, plaintext):
    # Initialisiert einen AES-Cipher im ECB-Modus mit dem gegebenen Schlüssel
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    # Padde den Klartext und verschlüssele ihn
    return encryptor.update(pad(plaintext)) + encryptor.finalize()

def aes_ecb_decrypt(key, ciphertext):
    # Initialisiert einen AES-Cipher im ECB-Modus zum Entschlüsseln
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    # Entschlüssele den Ciphertext und entferne das Padding
    return unpad(decryptor.update(ciphertext) + decryptor.finalize())

def aes_cbc_encrypt(key, iv, plaintext):
    # Initialisiert einen AES-Cipher im CBC-Modus mit Schlüssel und IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Padde den Klartext und verschlüssele ihn im CBC-Modus
    return encryptor.update(pad(plaintext)) + encryptor.finalize()

def aes_cbc_decrypt(key, iv, ciphertext):
    # Initialisiert einen AES-Cipher im CBC-Modus zum Entschlüsseln mit IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # Entschlüssele den Ciphertext und entferne das Padding
    return unpad(decryptor.update(ciphertext) + decryptor.finalize())


# === Fehlerausbreitung bei CBC testen ===
def test_cbc_error_propagation():
    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = b"A" * 32  # zwei AES-Blöcke à 16 Bytes

    ciphertext = aes_cbc_encrypt(key, iv, plaintext)

    # Bitflip im ersten Block des Ciphertexts
    corrupted = bytearray(ciphertext)
    corrupted[0] ^= 0x01  # Flip LSB des ersten Bytes
    corrupted = bytes(corrupted)

    try:
        decrypted = aes_cbc_decrypt(key, iv, corrupted)
    except Exception as e:
        decrypted = f"(Fehler beim Entschlüsseln: {str(e)})"

    table = [
        ["Original", plaintext],
        ["Fehlerhafte Entschlüsselung", decrypted]
    ]
    print(tabulate(table, headers=["Typ", "Inhalt"]))

# === Zeitvergleich (eigene Implementierung vs. Library) ===
def benchmark_encryptions():
    key = os.urandom(16)
    iv = os.urandom(16)
    data = os.urandom(1024 * 100)  # 100 KB zufällige Daten

    # Eigene ECB
    start = time.time()
    aes_ecb_encrypt(key, data)
    own_ecb_time = time.time() - start

    # Eigene CBC
    start = time.time()
    aes_cbc_encrypt(key, iv, data)
    own_cbc_time = time.time() - start

    # Library ECB
    cipher_ecb = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    start = time.time()
    enc = cipher_ecb.encryptor()
    enc.update(pad(data)) + enc.finalize()
    lib_ecb_time = time.time() - start

    # Library CBC
    cipher_cbc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    start = time.time()
    enc = cipher_cbc.encryptor()
    enc.update(pad(data)) + enc.finalize()
    lib_cbc_time = time.time() - start

    table = [
        ["ECB", "eigene Implementierung", f"{own_ecb_time:.5f} s"],
        ["CBC", "eigene Implementierung", f"{own_cbc_time:.5f} s"],
        ["ECB", "Library", f"{lib_ecb_time:.5f} s"],
        ["CBC", "Library", f"{lib_cbc_time:.5f} s"]
    ]
    print(tabulate(table, headers=["Modus", "Quelle", "Zeit"]))

# === Hauptprogramm ===
if __name__ == "__main__":
    print("=== Fehlerausbreitung in CBC (Bitflip im Ciphertext) ===")
    test_cbc_error_propagation()

    print("\n=== Zeitvergleich von ECB und CBC (eigene Implementierung vs. Library) ===")
    benchmark_encryptions()
