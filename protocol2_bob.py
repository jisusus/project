import socket
import threading
import argparse
import logging
import json
import random
import base64
import time
from math import isqrt
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def encrypt(key, msg):
    pad = BLOCK_SIZE - len(msg)
    msg = msg + pad * chr(pad)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(msg.encode())


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


def RSA_decrypt(encrypted_key, public, n):
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


def AES_decrypt(encrypted_message, decrypted_key):
    decrypted_message = []
    for key in decrypted_key:
        decrypted = decrypt(key, encrypted_message).decode()
        # decrypted = decrypted[0:-ord(decrypted[-1])]
        decrypted_message.append(decrypted)
    return decrypted_message


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def make_random_relatively_prime(a):
    b = random.randrange(400, 500)
    while gcd(a, b) != 1:
        b = random.randrange(400, 500)
    return b


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


def handler(conn, msg):
    random.seed(None)
    rsa_keypair = None
    symmetric_key = None

    while True:
        try:
            rbytes = conn.recv(1024)
            if not rbytes:
                break

            logging.debug("rbytes: {}".format(rbytes))
            rjs = rbytes.decode("utf-8")
            logging.debug("rjs: {}".format(rjs))
            rmsg = json.loads(rjs)
            logging.debug("rmsg: {}".format(rmsg))

            logging.info("[*] Received: {}".format(rjs))

            if rmsg["opcode"] == 0 and rmsg["type"] == "RSA":
                rsa_keypair = generate_rsa_keypair()
                e = rsa_keypair["public"]
                n = rsa_keypair["parameter"]["n"]
                smsg_1 = {
                    "opcode": 1,
                    "type": "RSA",
                    "public": e,
                    "parameter": {"n": n},
                }
                logging.debug("smsg_1: {}".format(smsg_1))
                sjs_1 = json.dumps(smsg_1)
                logging.debug("sjs_1: {}".format(sjs_1))
                sbytes_1 = sjs_1.encode("utf-8")
                logging.debug("sbytes_1: {}".format(sbytes_1))
                conn.send(sbytes_1)
                logging.info(
                    "[*] Sent RSA public key (e={}, n={}) to Alice".format(e, n)
                )

            elif rmsg["opcode"] == 2 and rmsg["type"] == "RSA":
                encrypted_key = rmsg["encrypted_key"]
                d = rsa_keypair["private"]
                n = rsa_keypair["parameter"]["n"]
                symmetric_key = RSA_decrypt(encrypted_key, d, n)
                logging.info("[*] Decrypted symmetric key: {}".format(symmetric_key))

            elif rmsg["opcode"] == 2 and rmsg["type"] == "AES":
                encrypted_msg_2 = base64.b64decode(rmsg["encryption"])
                decrypted_msg_2 = decrypt(symmetric_key, encrypted_msg_2).decode(
                    "utf-8"
                )
                decrypted_msg_2 = decrypted_msg_2[0 : -ord(decrypted_msg_2[-1])]
                logging.info(
                    "[*] Decrypted message from Alice: {}".format(decrypted_msg_2)
                )

                response_message = msg
                encrypted_response = encrypt(symmetric_key, response_message)
                encrypted_response = base64.b64encode(encrypted_response).decode(
                    "utf-8"
                )

                smsg_2 = {
                    "opcode": 2,
                    "type": "AES",
                    "encryption": encrypted_response,
                }
                logging.debug("smsg_2: {}".format(smsg_2))
                sjs_2 = json.dumps(smsg_2)
                logging.debug("sjs_2: {}".format(sjs_2))
                sbytes_2 = sjs_2.encode("utf-8")
                logging.debug("sbytes_2: {}".format(sbytes_2))
                conn.send(sbytes_2)
                logging.info("[*] Sent encrypted response: {}".format(sjs_2))

        except socket.error as e:
            logging.error(f"Socket error occurred: {e}")
            break

    conn.close()
    logging.info("[*] Connection closed.")

    # rbytes = conn.recv(1024)
    # logging.debug("rbytes: {}".format(rbytes))
    # rjs = rbytes.decode("ascii")
    # logging.debug("rjs: {}".format(rjs))
    # rmsg = json.loads(rjs)
    # logging.debug("rmsg: {}".format(rmsg))

    # logging.info("[*] Received: {}".format(rjs))

    # if rmsg["opcode"] == 0 and rmsg["type"] == "RSA":
    #     key = generate_rsa_keypair()
    #     e = key["public"]
    #     d = key["private"]
    #     n = key["parameter"]["n"]
    #     smsg_1 = {"opcode": 1, "type": "RSA", "public": e, "parameter": {"n": n}}
    #     logging.debug("smsg_1: {}".format(smsg_1))
    #     sjs_1 = json.dumps(smsg_1)
    #     logging.debug("sjs_1: {}".format(sjs_1))
    #     sbytes_1 = sjs_1.encode("ascii")
    #     logging.debug("sbytes_1: {}".format(sbytes_1))
    #     conn.send(sbytes_1)
    #     logging.info("[*] Sent RSA public key (e={}, n={}) to Alice".format(e, n))

    #     time.sleep(1)

    # elif rmsg["opcode"] == 2 and rmsg["type"] == "RSA":
    #     encrypted_key = rmsg["encrypted_key"]
    #     symmetric_key = RSA_decrypt(encrypted_key, e, n)
    #     logging.info("[*] Decrypted symmetric key: {}".format(symmetric_key))

    #     encrypted_msg = encrypt(symmetric_key, msg)
    #     encrypted_msg = base64.b64encode(encrypted_msg)

    #     smsg_2 = {
    #         "opcode": 2,
    #         "type": "AES",
    #         "encryption": encrypted_msg,
    #     }
    #     logging.debug("smsg_2: {}".format(smsg_2))
    #     sjs_2 = json.dumps(smsg_2)
    #     logging.debug("sjs_2: {}".format(sjs_2))
    #     sbytes_2 = sjs_2.encode("ascii")
    #     logging.debug("sbytes_2: {}".format(sbytes_2))
    #     conn.send(sbytes_2)
    #     logging.info("[*] Sent encrypted response: {}".format(sjs_2))

    #     time.sleep(1)

    # elif rmsg["opcode"] == 2 and rmsg["type"] == "AES":

    #     encrypted_msg_2 = base64.b64decode(rmsg["encryption"])
    #     decrypted_msg_2 = decrypt(symmetric_key, encrypted_msg_2)
    #     logging.info("[*] Decrypted message from Alice: {}".format(decrypted_msg_2))

    # conn.close()
    # logging.info("[*] Connection closed.")


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

        conn_handle = threading.Thread(
            target=handler,
            args=(
                conn,
                msg,
            ),
        )
        conn_handle.start()
        conn_handle.join()


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
