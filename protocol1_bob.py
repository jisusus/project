import socket
import threading
import argparse
import logging
import json
import random
import base64
from Crypto.PublicKey import RSA
from Crypto.Util import number

def generate_rsa_keypair():
    # p와 q는 400과 500 사이의 소수로 설정
    p = number.getPrime(9, randfunc=None)  # 9비트의 작은 소수(테스트용으로만 사용)
    q = number.getPrime(9, randfunc=None)
    while not (400 <= p < 500 and 400 <= q < 500):
        p = number.getPrime(9)
        q = number.getPrime(9)

    # RSA 키 쌍 생성
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = number.inverse(e, phi)

    public_key = e
    private_key = d

    # 전송할 데이터 구조 (Bob -> Alice)
    data = {
        "opcode": 0,
        "type": "RSAKey",
        "private": private_key,
        "public": public_key,
        "parameter": {"p": p, "q": q}
    }
    return data

def handler(conn):
    random.seed(None)

    rbytes = conn.recv(1024)
    logging.debug("rbytes: {}".format(rbytes))

    rjs = rbytes.decode("ascii")
    logging.debug("rjs: {}".format(rjs))

    rmsg = json.loads(rjs)
    logging.debug("rmsg: {}".format(rmsg))

    logging.info("[*] Received: {}".format(rjs))
    logging.info(" - opcode: {}".format(rmsg["opcode"]))
    logging.info(" - type: {}".format(rmsg["type"]))

    rsa = generate_rsa_keypair()
    logging.debug("rsa: {}".format(rsa))
    
    sjs = json.dumps(rsa)
    logging.debug("sjs: {}".format(sjs))

    sbytes = sjs.encode("ascii")
    logging.debug("sbytes: {}".format(sbytes))

    conn.send(sbytes)
    logging.info("[*] Sent: {}".format(sjs))

    conn.close()

def run(addr, port):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()

        logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))

        conn_handle = threading.Thread(target=handler, args=(conn,))
        conn_handle.start()
        conn_handle.join()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port)

if __name__ == "__main__":
    main()
