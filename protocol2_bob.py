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


def is_prime_number(x):
    for i in range(2, x):
        if x % i == 0:
            return False
    return True


def make_prime_number(a, b):
    p = random.randrange(a, b)
    if is_prime_number(p):
        return p
    else:
        return make_prime_number(a, b)


def make_mulitiplicative_inverse(a, b):
    y0, y1, r = 0, 1, 1
    while b != 0:
        q, r = divmod(a, b)
        y0, y1 = y1, y0 - q * y1
        a, b = b, r
    return y0 + a if y0 < 0 else y0


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


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


def RSA_decrypt(encrypted_key, public, n, type):
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

    decrypted_key = []

    for c in encrypted_key:
        decrypted_key.append(c**d % n)

    return decrypted_key


def AES_decrypt(encrypted_message, decrypted_key):
    decrypted_message = []
    for key in decrypted_key:
        decrypted = decrypt(key, encrypted_message).decode()
        decrypted = decrypted[0 : -ord(decrypted[-1])]
        decrypted_message.append(decrypted)
    return decrypted_message


def make_random_relatively_prime(a):
    b = random.randrange(400, 500)
    while gcd(a, b) != 1:
        b = random.randrange(400, 500)
    return b


def generate_rsa_keypair():
    p = make_prime_number(400, 500)
    q = make_prime_number(400, 500)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = make_random_relatively_prime(phi)
    d = make_mulitiplicative_inverse(phi, e)
    data = {
        "opcode": 1,
        "type": "RSA",
        "public": e,
        "private": d,
        "parameter": {"n": n},
    }
    return data


rsa_keys = None


def handler(conn, msg):
    global rsa_keys
    random.seed(None)

    try:
        # Step 1: Receive RSA Key Request from Alice
        rbytes = conn.recv(1024)
        if not rbytes:
            logging.error("Received an empty response.")
            conn.close()
            return
        rjs = rbytes.decode("ascii")
        rmsg = json.loads(rjs)

        if rmsg["opcode"] == 0 and rmsg["type"] == "RSA":
            # Step 2: Generate and Send RSA Key Pair
            rsa_keys = generate_rsa_keypair()
            e = rsa_keys["public"]
            d = rsa_keys["private"]
            n = rsa_keys["parameter"]["n"]
            smsg = {"opcode": 1, "type": "RSA", "public": e, "parameter": {"n": n}}
            sjs = json.dumps(smsg)
            conn.send(sjs.encode("ascii"))
            logging.info("[*] Sent RSA public key (e={}, n={}) to Alice".format(e, n))

        # Step 3: Receive Encrypted Symmetric Key
        rbytes_2 = conn.recv(1024)
        rjs_2 = rbytes_2.decode("ascii")
        rmsg_2 = json.loads(rjs_2)
        encrypted_key = rmsg_2["encrypted_key"]
        symmetric_key = rsa_decrypt(encrypted_key, d, n)
        logging.info("[*] Decrypted symmetric key: {}".format(symmetric_key))

        # Step 4: Receive AES-encrypted message from Alice
        rbytes_3 = conn.recv(1024)
        rjs_3 = rbytes_3.decode("ascii")
        rmsg_3 = json.loads(rjs_3)
        encrypted_msg = base64.b64decode(rmsg_3["encryption"])
        decrypted_msg = decrypt(symmetric_key, encrypted_msg)
        logging.info("[*] Decrypted message from Alice: {}".format(decrypted_msg))

        # Step 5: Send Response to Alice
        response_msg = "Message received: {}".format(decrypted_msg.decode("utf-8"))
        encrypted_response = encrypt(symmetric_key, response_msg)
        smsg_4 = {
            "opcode": 2,
            "type": "AES",
            "encryption": base64.b64encode(encrypted_response).decode("utf-8"),
        }
        sjs_4 = json.dumps(smsg_4)
        conn.send(sjs_4.encode("ascii"))
        logging.info("[*] Sent response to Alice: {}".format(sjs_4))

    except Exception as e:
        logging.error(f"An error occurred: {e}")

    finally:
        conn.close()
        logging.info("[*] Connection closed to Alice.")


def run(addr, port, msg):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))
    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()
        logging.info(
            "[*] Bob accepts the connection from {}:{}".format(info[0], info[1])
        )
        conn_handle = threading.Thread(target=handler, args=(conn, msg))
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
    return parser.parse_args()


def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)
    run(args.addr, args.port, args.message)


if __name__ == "__main__":
    main()
