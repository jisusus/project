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
    encrypted_message = [pow(ord(char), e, n) for char in message]
    return encrypted_message


def rsa_decrypt(encrypted_message, d, n):
    decrypted_message = bytes([pow(char, d, n) for char in encrypted_message])
    return decrypted_message


def generate_rsa_keypair():
    p = random.randint(200, 300)
    q = random.randint(200, 300)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(1, phi)
    while gcd(e, phi) != 1:
        e = random.randint(1, phi)
    d = multiplicative_inverse(e, phi)
    return {"public": e, "private": d, "parameter": {"n": n}}


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def multiplicative_inverse(e, phi):
    d, x1, x2, y1 = 0, 0, 1, 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi, e = e, temp2
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        x2, x1 = x1, x
        d, y1 = y1, y

    if temp_phi == 1:
        return d + phi


def handler(conn, rsa_keys_1, msg):
    try:
        # Step 1: Receive RSA Key Request from Alice
        rbytes_1_1 = conn.recv(1024)
        rjs_1_1 = rbytes_1_1.decode("utf-8")
        rmsg_1_1 = json.loads(rjs_1_1)
        logging.debug("rmsg_1_1: {}".format(rmsg_1_1))

        if rmsg_1_1["opcode"] == 0 and rmsg_1_1["type"] == "RSA":
            # Step 2: Send RSA Public Key to Alice
            e = rsa_keys_1["public"]
            n = rsa_keys_1["parameter"]["n"]
            smsg_1_1 = {"opcode": 1, "type": "RSA", "public": e, "parameter": {"n": n}}
            sjs_1_1 = json.dumps(smsg_1_1)
            conn.send(sjs_1_1.encode("utf-8"))
            logging.info("[*] Sent RSA public key (e={}, n={}) to Alice".format(e, n))

        # Step 3: Receive Encrypted Symmetric Key from Alice
        rbytes_1_2 = conn.recv(1024)
        rjs_1_2 = rbytes_1_2.decode("utf-8")
        rmsg_1_2 = json.loads(rjs_1_2)
        logging.debug("rmsg_1_2: {}".format(rmsg_1_2))

        if rmsg_1_2["opcode"] == 2 and rmsg_1_2["type"] == "RSA":
            encrypted_key = rmsg_1_2["encrypted_key"]
            d = rsa_keys_1["private"]
            n = rsa_keys_1["parameter"]["n"]
            symmetric_key = rsa_decrypt(encrypted_key, d, n)
            logging.info("[*] Decrypted symmetric key: {}".format(symmetric_key))

            # Step 4: Encrypt Response with Symmetric Key and Send to Alice
            encrypted_msg = encrypt(symmetric_key, msg)
            smsg_1_2 = {
                "opcode": 2,
                "type": "AES",
                "encryption": base64.b64encode(encrypted_msg).decode("utf-8"),
            }
            sjs_1_2 = json.dumps(smsg_1_2)
            conn.send(sjs_1_2.encode("utf-8"))
            logging.info("[*] Sent AES-encrypted message to Alice: {}".format(sjs_1_2))

    except Exception as e:
        logging.error("An error occurred: {}".format(e))
    finally:
        conn.close()
        logging.info("[*] Connection closed with Alice.")


def run(addr, port, msg):
    rsa_keys_1 = generate_rsa_keypair()
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))
    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()
        logging.info(
            "[*] Bob accepts the connection from {}:{}".format(info[0], info[1])
        )
        conn_handle = threading.Thread(target=handler, args=(conn, rsa_keys_1, msg))
        conn_handle.start()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<bob's IP address>",
        help="Bob's IP address",
        type=str,
        default="0.0.0.0",
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<bob's open port>",
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
