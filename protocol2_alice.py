import socket
import argparse
import logging
import json
import random
import base64
import time
from math import isqrt
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(encrypted)


def encrypt(key, msg):
    pad = BLOCK_SIZE - len(msg)
    msg = msg + pad * chr(pad)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(msg.encode())


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


def RSA_encrypt(message, e, n):
    encrypted_message = [pow(byte, e, n) for byte in message]
    return encrypted_message


def AES_decrypt(encrypted_message, decrypted_key):
    decrypted_message = []
    for key in decrypted_key:
        decrypted = decrypt(key, encrypted_message).decode()
        # decrypted = decrypted[0:-ord(decrypted[-1])]
        decrypted_message.append(decrypted)
    return decrypted_message


def run(addr, port, msg):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    random.seed(None)

    smsg_1 = {"opcode": 0, "type": "RSA"}
    logging.debug("smsg_1: {}".format(smsg_1))
    sjs_1 = json.dumps(smsg_1)
    logging.debug("sjs_1: {}".format(sjs_1))
    sbytes_1 = sjs_1.encode("utf-8")
    logging.debug("sbytes_1: {}".format(sbytes_1))
    conn.send(sbytes_1)
    logging.info("[*] Sent: {}".format(sbytes_1))

    time.sleep(1)

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

    symmetric_key = bytes([random.randint(0, 255) for _ in range(32)])
    encrypted_key = RSA_encrypt(symmetric_key, e, n)
    logging.info("[*] Generated symmetric key: {}".format(symmetric_key))
    logging.info("[*] Encrypted symmetric key: {}".format(encrypted_key))

    smsg_2 = {
        "opcode": 2,
        "type": "RSA",
        "encrypted_key": encrypted_key,
    }
    logging.debug("smsg_2: {}".format(smsg_2))
    sjs_2 = json.dumps(smsg_2)
    logging.debug("sjs_2: {}".format(sjs_2))
    sbytes_2 = sjs_2.encode("utf-8")
    logging.debug("sbytes_2: {}".format(sbytes_2))
    conn.send(sbytes_2)
    logging.info("[*] Sent encrypted symmetric key: {}".format(sjs_2))

    time.sleep(1)

    rbytes_2 = conn.recv(1024)
    rjs_2 = rbytes_2.decode("utf-8")
    rmsg_2 = json.loads(rjs_2)
    logging.debug("rmsg_2: {}".format(rmsg_2))
    logging.info("[*] Received encrypted response: {}".format(rjs_2))

    encrypted_response = base64.b64decode(rmsg_2["encryption"])

    decrypted_response = decrypt(symmetric_key, encrypted_response).decode("utf-8")
    decrypted_response = decrypted_response[0 : -ord(decrypted_response[-1])]
    logging.info("[*] Decrypted message from Bob: {}".format(decrypted_response))

    encrypted_msg = encrypt(symmetric_key, msg)
    smsg_3 = {
        "opcode": 2,
        "type": "AES",
        "encryption": base64.b64encode(encrypted_msg).decode("utf-8"),
    }
    logging.debug("smsg_3: {}".format(smsg_3))
    sjs_3 = json.dumps(smsg_3)
    logging.debug("sjs_3: {}".format(sjs_3))
    sbytes_3 = sjs_3.encode("utf-8")
    logging.debug("sbytes_3: {}".format(sbytes_3))
    conn.send(sbytes_3)
    logging.info("[*] Sent AES-encrypted msg: {}".format(sjs_3))

    time.sleep(1)

    # response_message = msg
    # encrypted_response_msg = encrypt(symmetric_key, response_message)

    # smsg_4 = {
    #     "opcode": 2,
    #     "type": "AES",
    #     "encryption": base64.b64encode(encrypted_response_msg).decode("utf-8"),
    # }
    # logging.debug("smsg_4: {}".format(smsg_4))
    # sjs_4 = json.dumps(smsg_4)
    # logging.debug("sjs_4: {}".format(sjs_4))
    # sbytes_4 = sjs_4.encode("utf-8")
    # logging.debug("sbytes_4: {}".format(sbytes_4))
    # conn.send(sbytes_4)
    # logging.info("[*] Sent AES-encrypted response message: {}".format(sjs_4))

    conn.close()

    # smsg = {}
    # smsg["name"] = "Alice"
    # key = random.randbytes(32)
    # smsg["random"] = base64.b64encode(key).decode()
    # logging.debug("smsg: {}".format(smsg))

    # sjs = json.dumps(smsg)
    # logging.debug("sjs: {}".format(sjs))

    # sbytes = sjs.encode("ascii")
    # logging.debug("sbytes: {}".format(sbytes))

    # conn.send(sbytes)
    # logging.info("[*] Sent: {}".format(sjs))

    # rbytes = conn.recv(1024)
    # logging.debug("rbytes: {}".format(rbytes))

    # rjs = rbytes.decode("ascii")
    # logging.debug("rjs: {}".format(rjs))

    # rmsg = json.loads(rjs)
    # logging.debug("rmsg: {}".format(rmsg))

    # logging.info("[*] Received: {}".format(rjs))
    # logging.info(" - name: {}".format(rmsg["name"]))
    # logging.info(" - encryption: {}".format(rmsg["encryption"]))

    # encrypted = base64.b64decode(rmsg["encryption"].encode())
    # decrypted = decrypt(key, encrypted).decode()
    # decrypted = decrypted[0:-ord(decrypted[-1])]
    # logging.info("[*] Decrypted: {}".format(decrypted))

    # conn.close()


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
