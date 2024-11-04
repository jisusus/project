import socket
import threading
import argparse
import logging
import json
import random
import base64
import random

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
    if a<0 and b<0:
        q = - (a // -b)
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
        y = y0 - y1*q
        y0 = y1
        y1 = y
        a = b
        b = r    
    return y0

def run(a, b):
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
    b = random.randrange(400, 500)
    if gcd(a, b) == 1:
        return b
    else:
        return make_random_relatively_prime(a)
    
def generate_rsa_keypair():
    # p와 q는 400과 500 사이의 소수로 설정
    p = make_prime_number(400, 500)
    q = make_prime_number(400, 500)

    # RSA 키 쌍 생성
    n = p * q
    phi = (p - 1) * (q - 1)
    e = make_random_relatively_prime(phi)
    d = run(phi, e)

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
