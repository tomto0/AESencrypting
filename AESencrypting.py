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
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(pad(plaintext)) + encryptor.finalize()

def aes_ecb_decrypt(key, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return unpad(decryptor.update(ciphertext) + decryptor.finalize())

def aes_cbc_encrypt(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(pad(plaintext)) + encryptor.finalize()

def aes_cbc_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return unpad(decryptor.update(ciphertext) + decryptor.finalize())

# === Erweiterte Modi: OFB, CTR, CFB ===
def aes_ofb_encrypt(key, iv, plaintext):
    # Initialisiert AES im OFB-Modus (Output Feedback Mode)
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Verschluesselt den Klartext im Strommodus (kein Padding noetig)
    return encryptor.update(plaintext) + encryptor.finalize()

def aes_ctr_encrypt(key, nonce, plaintext):
    # Initialisiert AES im CTR-Modus (Counter Mode) mit einem Zaehler (Nonce)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    # Verschluesselt den Klartext blockweise, aber unabhaengig (parallelisierbar, kein Padding noetig)
    return encryptor.update(plaintext) + encryptor.finalize()

def aes_cfb_encrypt(key, iv, plaintext, segment_size=128):
    # Initialisiert AES im CFB-Modus mit waehlbarer Segmentgroesse
    # 128 Bit: Standardblockgroesse, 8 Bit: Byteweises Feedback
    if segment_size == 128:
        mode = modes.CFB(iv)
    elif segment_size == 8:
        mode = modes.CFB8(iv)
    else:
        raise ValueError("Nur 8 oder 128 Bit Segmentgroesse werden unterstuetzt.")
    cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
    encryptor = cipher.encryptor()
    # Verschluesselt den Klartext segmentweise (kein Padding noetig)
    return encryptor.update(plaintext) + encryptor.finalize()

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

# === Benchmark für OFB, CTR, CFB (eigene Implementierungen) ===
def benchmark_stream_modes():
    key = os.urandom(16)
    iv = os.urandom(16)
    nonce = os.urandom(16)
    data = os.urandom(1024 * 100)

    results = []

    # OFB
    start = time.time()
    aes_ofb_encrypt(key, iv, data)
    results.append(["OFB", "eigene Implementierung", f"{time.time() - start:.5f} s"])

    # CTR
    start = time.time()
    aes_ctr_encrypt(key, nonce, data)
    results.append(["CTR", "eigene Implementierung", f"{time.time() - start:.5f} s"])

    # CFB 128 Bit
    start = time.time()
    aes_cfb_encrypt(key, iv, data, segment_size=128)
    results.append(["CFB (128-bit)", "eigene Implementierung", f"{time.time() - start:.5f} s"])

    # CFB 8 Bit
    start = time.time()
    aes_cfb_encrypt(key, iv, data, segment_size=8)
    results.append(["CFB (8-bit)", "eigene Implementierung", f"{time.time() - start:.5f} s"])

    print(tabulate(results, headers=["Modus", "Quelle", "Zeit"]))

# === Vergleich CFB 8 Bit vs. 128 Bit ===
def compare_cfb_segment_sizes():
    key = os.urandom(16)
    iv = os.urandom(16)
    data = os.urandom(1024 * 100)

    results = []
    for bits in [8, 128]:
        start = time.time()
        aes_cfb_encrypt(key, iv, data, segment_size=bits)
        elapsed = time.time() - start
        results.append([f"CFB mit {bits} Bit", f"{elapsed:.5f} s"])

    print(tabulate(results, headers=["Variante", "Zeit"]))

# === Hauptprogramm ===
if __name__ == "__main__":
    print("=== Fehlerausbreitung in CBC (Bitflip im Ciphertext) ===")
    test_cbc_error_propagation()

    print("\n=== Zeitvergleich von ECB und CBC (eigene Implementierung vs. Library) ===")
    benchmark_encryptions()

    print("\n=== Zeitvergleich der Modi OFB, CTR, CFB ===")
    benchmark_stream_modes()

    print("\n=== Vergleich der Segmentgrößen im CFB-Modus ===")
    compare_cfb_segment_sizes()
