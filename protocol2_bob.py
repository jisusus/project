import socket
import threading
import argparse
import logging
import json
import random
import base64
import random
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


def rsa_encrypt(message, e, n):
    encrypted_message = [pow(ord(char), e, n) for char in message]
    return encrypted_message


def rsa_decrypt(encrypted_message, d, n):
    decrypted_message = "".join([chr(pow(char, d, n)) for char in encrypted_message])
    return decrypted_message


def is_prime_number(x):
    for i in range(2, x):
        if x % i == 0:
            return False
    return True


def make_prime_number(a, b):
    p = random.randrange(a, b)
    if is_prime_number(p) == True:
        return p
    else:
        return make_prime_number(a, b)


def mod(a, b):
    if a < 0 and b < 0:
        q = -(a // -b)
        r = a - (b * q)
    elif b == 0:
        print("Please enter non-zero at b")
    else:
        q = a // b
        r = a % b
    return q, r


def multiplicative_inverse(a, b):
    y0 = 0
    y1 = 1
    r = 1
    a = a
    b = b

    while r != 0:
        q, r = mod(a, b)
        y = y0 - y1 * q
        y0 = y1
        y1 = y
        a = b
        b = r
    return y0


def make_mulitiplicative_inverse(a, b):
    y = multiplicative_inverse(a, b)
    while y < 0:
        y += a
    return y


def gcd(a, b):
    if b == 0:
        return a
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)


def make_random_relatively_prime(a):
    b = random.randrange(20000, 30000)
    if gcd(a, b) == 1:
        return b
    else:
        return make_random_relatively_prime(a)


def generate_rsa_keypair():
    p = make_prime_number(20000, 30000)
    q = make_prime_number(20000, 30000)

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

    rbytes = conn.recv(1024)
    if not rbytes:
        logging.error("Received an empty response.")
        conn.close()
        return
    logging.debug("rbytes: {}".format(rbytes))

    rjs = rbytes.decode("ascii")
    logging.debug("rjs: {}".format(rjs))

    try:
        rmsg = json.loads(rjs)
    except json.JSONDecodeError as e:
        logging.error("JSON Decode Error: {}".format(e))
        conn.close()
        return
    logging.debug("rmsg: {}".format(rmsg))

    if rmsg["opcode"] == 0 and rmsg["type"] == "RSA":
        rsa_keys = generate_rsa_keypair()
        e = rsa_keys["public"]
        d = rsa_keys["private"]
        n = rsa_keys["parameter"]["n"]
        smsg = {"opcode": 1, "type": "RSA", "public": e, "parameter": {"n": n}}
        sjs = json.dumps(smsg)
        conn.send(sjs.encode("ascii"))
        logging.info("[*] Sent RSA public key (e={}, n={}) to Alice".format(e, n))

    elif rmsg["opcode"] == 2 and rmsg["type"] == "RSA":
        if not rsa_keys:
            logging.error("RSA keys are not available.")
            conn.close()
            return

        d = rsa_keys["private"]
        n = rsa_keys["parameter"]["n"]
        encrypted_key = rmsg["encrypted_key"]
        symmetric_key = rsa_decrypt(encrypted_key, d, n).encode("latin-1")
        logging.info("[*] Decrypted symmetric key: {}".format(symmetric_key))

        encrypted_msg = encrypt(symmetric_key.encode("utf-8"), msg)
        smsg = {
            "opcode": 2,
            "type": "AES",
            "encryption": base64.b64encode(encrypted_msg).decode("utf-8"),
        }
        sjs = json.dumps(smsg)
        conn.send(sjs.encode("ascii"))
        logging.info("[*] Sent AES-encrypted message to Alice: {}".format(sjs))

    elif rmsg["opcode"] == 2 and rmsg["type"] == "AES":
        encrypted_msg = base64.b64decode(rmsg["encryption"])
        decrypted_msg = decrypt(symmetric_key.encode("utf-8"), encrypted_msg)
        logging.info("[*] Decrypted message from Alice: {}".format(decrypted_msg))

    conn.close()
    logging.info("[*] Connection close to Alice.")


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
