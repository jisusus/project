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
        print("no multiplicative inverse")
        return None
    else:
        return x % phi_n

def RSA_decrypte(encrypted_key, public, n, type):
    for i in range(2, isqrt(n) + 1):
        if n % i == 0:
            p = i 
            q = n // i
    phi_n = (p - 1) * (q - 1)
    d = modular_inverse(public, phi_n)

    decrypted_key = []

    for c in encrypted_key:
        decrypted_key.append(c**d % n)

    return decrypted_key

def AES_decrypte(encrypted_message, decrypted_key):
    decrypted_message = []
    for key in decrypted_key:
        decrypted = decrypt(key, encrypted_message).decode()
        # decrypted = decrypted[0:-ord(decrypted[-1])]
        decrypted_message.append(decrypted)
    return decrypted_message



def read_file(path):
    with open(path, 'r') as log_file:
        log_data = log_file.readlines()

    for line in log_data:
        log = json.loads(line.strip())

        if log["opcode"] == 1:
            public = log["public"]
            n = log["parameter"]["n"]
            print(public, n)

        if log["opcode"] == 2:
            type = log["type"]
            if type == "RSA":
                encrypted_key = log["encrypted_key"]
                decrypted_key = RSA_decrypte(encrypted_key, public, n, type)
                print(decrypted_key)
            elif type == "AES":
                encrypted_message_base64 = log["encryption"]
                encrypted_message = base64.b64decode(encrypted_message_base64)
                decrypted_message = AES_decrypte(encrypted_message, decrypted_key)
                print(f"Decrypted message = {decrypted_message}")

def main():
    current_path = "adv_protocol_two.log"
    read_file(current_path)
    
if __name__ == "__main__":
    main()
