import socket
import threading
import argparse
import logging
import json
import random
import base64
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def encrypt(key, msg):
    pad = BLOCK_SIZE - len(msg) % BLOCK_SIZE
    msg = msg + pad * chr(pad)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(msg.encode())


def decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(encrypted)


def rsa_encrypt(message, e, n):
    encrypted_message = [pow(byte, e, n) for byte in message]
    return encrypted_message


def rsa_decrypt(encrypted_message, d, n):
    decrypted_message = bytes([pow(char, d, n) % 256 for char in encrypted_message])
    return decrypted_message


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


def RSA_decrypt(encrypted_key, public, n):
    p, q = None, None
    for i in range(2, n):
        if n % i == 0:
            p = i
            q = n // i
            break
    if p is None or q is None:
        raise ValueError("Failed to factorize n")
    phi_n = (p - 1) * (q - 1)
    d = modular_inverse(public, phi_n)

    decrypted_key = rsa_decrypt(encrypted_key, d, n)
    return decrypted_key


def AES_decrypt(encrypted_message, decrypted_key):
    decrypted = decrypt(decrypted_key, encrypted_message).decode()
    pad = ord(decrypted[-1])
    return decrypted[:-pad]


def run(addr, port, msg):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    random.seed(None)

    # Step 1: Send RSA Key Request
    smsg_1 = {"opcode": 0, "type": "RSA"}
    sjs_1 = json.dumps(smsg_1)
    logging.debug("smsg_1: {}".format(smsg_1))
    conn.send(sjs_1.encode("utf-8"))
    logging.info("[*] Sent: {}".format(sjs_1))

    # Step 2: Receive RSA Public Key
    rbytes_1 = conn.recv(1024)
    rjs_1 = rbytes_1.decode("utf-8")
    rmsg_1 = json.loads(rjs_1)
    logging.debug("rmsg_1: {}".format(rmsg_1))
    logging.info("[*] Received: {}".format(rjs_1))
    logging.info(" - opcode: {}".format(rmsg_1["opcode"]))
    logging.info(" - type: {}".format(rmsg_1["type"]))
    logging.info(" - public: {}".format(rmsg_1["public"]))
    logging.info(" - parameter: {}".format(rmsg_1["parameter"]))

    e = rmsg_1["public"]
    n = rmsg_1["parameter"]["n"]
    logging.info("[*] Received RSA public key (e={}, n={})".format(e, n))

    # Step 3: Generate Symmetric Key and Encrypt with RSA Public Key
    symmetric_key = bytes([random.randint(0, 255) for _ in range(16)])
    encrypted_key = rsa_encrypt(symmetric_key, e, n)
    logging.info("[*] Generated symmetric key: {}".format(symmetric_key))
    logging.info("[*] Encrypted symmetric key: {}".format(encrypted_key))

    smsg_2 = {"opcode": 2, "type": "RSA", "encrypted_key": encrypted_key}
    sjs_2 = json.dumps(smsg_2)
    conn.send(sjs_2.encode("utf-8"))
    logging.info("[*] Sent encrypted symmetric key to Bob: {}".format(sjs_2))

    # Step 4: Encrypt Message with Symmetric Key and Send to Bob
    encrypted_msg = encrypt(symmetric_key, msg)
    smsg_3 = {
        "opcode": 2,
        "type": "AES",
        "encryption": base64.b64encode(encrypted_msg).decode("utf-8"),
    }
    sjs_3 = json.dumps(smsg_3)
    conn.send(sjs_3.encode("utf-8"))
    logging.info("[*] Sent AES-encrypted message to Bob: {}".format(sjs_3))

    # Step 5: Receive Response from Bob
    rbytes_2 = conn.recv(1024)
    rjs_2 = rbytes_2.decode("utf-8")
    rmsg_2 = json.loads(rjs_2)
    encrypted_response = base64.b64decode(rmsg_2["encryption"])
    decrypted_response = AES_decrypt(encrypted_response, symmetric_key)
    logging.info("[*] Decrypted message from Bob: {}".format(decrypted_response))

    conn.close()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<bob's address>",
        help="Bob's address",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<bob's port>",
        help="Bob's port",
        type=int,
        required=True,
    )
    parser.add_argument(
        "-m", "--message", metavar="<message>", help="Message", type=str, required=True
    )
    parser.add_argument(
        "-l",
        "--log",
        metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>",
        help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)",
        type=str,
        default="INFO",
    )
    args = parser.parse_args()
    return args


def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port, args.message)


if __name__ == "__main__":
    main()
