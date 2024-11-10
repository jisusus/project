import json
from math import isqrt
import base64
from Crypto.Cipher import AES

def decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(encrypted)

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    else:
        gcd, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

def modular_inverse(e, phi_n):
    gcd, x, _ = extended_gcd(e, phi_n)
    if gcd != 1:
        print("No multiplicative inverse exists.")
        return None
    else:
        return x % phi_n

def RSA_decrypte(encrypted_key, public, n):
    p, q = None, None
    for i in range(2, isqrt(n) + 1):
        if n % i == 0:
            p = i
            q = n // i
            break
    if p is None or q is None:
        raise ValueError("Failed to factorize n into p and q.")

    phi_n = (p - 1) * (q - 1)
    d = modular_inverse(public, phi_n)
    if d is None:
        raise ValueError("Failed to compute modular inverse of the public key.")

    decrypted_key = [pow(c, d, n) for c in encrypted_key]
    return decrypted_key

def AES_decrypte(encrypted_message, decrypted_key):
    key = bytes(decrypted_key)
    encrypted_message_bytes = base64.b64decode(encrypted_message)

    decrypted = decrypt(key, encrypted_message_bytes)
    padding_length = decrypted[-1]
    return decrypted[:-padding_length]

def read_file(path):
    with open(path, 'r') as log_file:
        log_data = log_file.readlines()

    public, n, decrypted_key = None, None, None

    for line in log_data:
        log = json.loads(line.strip())

        if log["opcode"] == 1:
            public = log["public"]
            n = log["parameter"]["n"]
            print("Public key and modulus received:", public, n)

        if log["opcode"] == 2:
            if log["type"] == "RSA":
                encrypted_key = log["encrypted_key"]
                decrypted_key = RSA_decrypte(encrypted_key, public, n)
                print("Decrypted RSA key:", decrypted_key)

            elif log["type"] == "AES" and decrypted_key is not None:
                encrypted_message_base64 = log["encryption"]
                decrypted_message = AES_decrypte(encrypted_message_base64, decrypted_key)
                print("Decrypted AES message:", decrypted_message.decode())

def main():
    current_path = input()
    read_file(current_path)

if __name__ == "__main__":
    main()
