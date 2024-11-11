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
    p = make_prime_number(400, 500)
    q = make_prime_number(400, 500)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = make_random_relatively_prime(phi)
    d = make_mulitiplicative_inverse(phi, e)
    return {"public": e, "private": d, "parameter": {"n": n}, "prime": {"p": p, "q": q}}


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


def make_random_relatively_prime(a):
    b = random.randrange(400, 500)
    if gcd(a, b) == 1:
        return b
    else:
        return make_random_relatively_prime(a)


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


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


def handler(conn, rsa_keys_1, msg):
    try:
        # Step 1: Receive RSA Key Request from Alice
        rbytes_1_1 = conn.recv(1024)
        rjs_1_1 = rbytes_1_1.decode()
        rmsg_1_1 = json.loads(rjs_1_1)
        logging.debug("rmsg_1_1: {}".format(rmsg_1_1))

        if rmsg_1_1["opcode"] == 0 and rmsg_1_1["type"] == "RSA":
            # Step 2: Send RSA Public Key to Alice
            e = rsa_keys_1["public"]
            n = rsa_keys_1["parameter"]["n"]
            smsg_1_1 = {"opcode": 1, "type": "RSA", "public": e, "parameter": {"n": n}}
            sjs_1_1 = json.dumps(smsg_1_1)
            conn.send(sjs_1_1.encode())
            logging.info("[*] Sent RSA public key (e={}, n={}) to Alice".format(e, n))

        # Step 3: Receive Encrypted Symmetric Key from Alice
        rbytes_1_2 = conn.recv(1024)
        rjs_1_2 = rbytes_1_2.decode()
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
                "encryption": base64.b64encode(encrypted_msg).decode(),
            }
            sjs_1_2 = json.dumps(smsg_1_2)
            conn.send(sjs_1_2.encode())
            logging.info("[*] Sent AES-encrypted message to Alice: {}".format(sjs_1_2))

            rbytes_2 = conn.recv(1024)
            rjs_2 = rbytes_2.decode()
            if not rjs_2:
                logging.error("Received an empty response from Alice.")
                conn.close()
                return

            rmsg_2 = json.loads(rjs_2)
            logging.info("[*] Received message from Alice: {}".format(rmsg_2))

            encrypted_response = base64.b64decode(rmsg_2["encryption"])
            decrypted_response = decrypt(symmetric_key, encrypted_response).decode()
            decrypted_response = decrypted_response[0 : -ord(decrypted_response[-1])]
            logging.info(
                "[*] Decrypted message from Alice: {}".format(decrypted_response)
            )

    except Exception as e:
        logging.error("An error occurred: {}".format(e))
    finally:
        conn.close()
        logging.info("[*] Connection closed with Alice.")


def run(addr, port, msg):
    Alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    Alice.bind((addr, port))
    Alice.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = Alice.accept()
        logging.info(
            "[*] Alice accepts the connection from {}:{}".format(info[0], info[1])
        )
        rsa_keys_1 = generate_rsa_keypair()
        logging.debug("RSA keypair: {}".format(rsa_keys_1))
        conn_handle = threading.Thread(target=handler, args=(conn, rsa_keys_1, msg))
        conn_handle.start()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<Alice's IP address>",
        help="Alice's IP address",
        type=str,
        default="0.0.0.0",
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<Alice's open port>",
        help="Alice's port",
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
