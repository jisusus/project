import socket
import threading
import argparse
import logging
import json
import random
import base64
from Crypto.Cipher import AES

BLOCK_SIZE = 16

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
    
def make_generator(a):
    i = random.randrange(1, a)
    remainder = set()
    
    for j in range(1, a):
        q, r = mod(i ** j, a)
        remainder.add(r)
        
    if len(remainder) == a-1:
        return i
    else:
        return make_generator(a)
    
def generate_DH_keypair():
    p = make_prime_number(400, 500)
    g = make_generator(p)
    b = random.randrange(1, p)
    public_key = (g ** b) % p
    
    data = {
        "opcode": 1,
        "type": "DH",
        "public": public_key,
        "parameter": {"p": p, "g": g}
    }
    return p, b, data
    
def encrypt(key, msg):
    pad = BLOCK_SIZE - len(msg)
    msg = msg + pad * chr(pad)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(msg.encode())

def decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(encrypted)

def handler(conn, msg):
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

    p, b, smsg = generate_DH_keypair()
    logging.debug("smsg: {}".format(smsg))

    sjs = json.dumps(smsg)
    logging.debug("sjs: {}".format(sjs))

    sbytes = sjs.encode("ascii")
    logging.debug("sbytes: {}".format(sbytes))

    conn.send(sbytes)

    rbytes_1 = conn.recv(1024)
    logging.debug("rbytes: {}".format(rbytes_1))
    
    rjs_1 = rbytes_1.decode("ascii")
    logging.debug("rjs: {}".format(rjs_1))
    
    rmsg_1 = json.loads(rjs_1)
    logging.debug("rmsg: {}".format(rmsg_1))

    logging.info("[*] Received: {}".format(rjs_1))
    logging.info(" - opcode: {}".format(rmsg_1["opcode"]))
    logging.info(" - type: {}".format(rmsg_1["type"]))
    logging.info(" - public: {}".format(rmsg_1["public"]))
    
    public_alice = rmsg_1["public"]
    DH_shared_secret = (public_alice ** b) % p
    
    AES_key = DH_shared_secret.to_bytes(2, byteorder = "big") * 16
    
    smsg_2 = {}
    smsg_2["opcode"] = 2
    smsg_2["type"] = "AES"
    encrypted = encrypt(AES_key, msg)
    
    smsg_2["encryption"] = base64.b64encode(encrypted).decode()
    logging.debug("smsg: {}".format(smsg_2))

    sjs_2 = json.dumps(smsg_2)
    logging.debug("sjs: {}".format(sjs_2))

    sbytes_2 = sjs_2.encode("ascii")
    logging.debug("sbytes: {}".format(sbytes_2))

    conn.send(sbytes_2)
    logging.info("[*] Sent: {}".format(sjs))
    
    rbytes_2 = conn.recv(1024)
    logging.debug("rbytes: {}".format(rbytes))

    rjs_2 = rbytes_2.decode("ascii")
    logging.debug("rjs: {}".format(rjs_2))

    rmsg_2 = json.loads(rjs_2)
    logging.debug("rmsg: {}".format(rmsg_2))

    logging.info("[*] Received: {}".format(rjs_2))
    logging.info(" - opcode: {}".format(rmsg_2["opcode"]))
    logging.info(" - type: {}".format(rmsg_2["type"]))
    logging.info(" - encryption: {}".format(rmsg_2["encryption"]))
    
    decrypted_msg = decrypt(AES_key, base64.b64decode(rmsg_2["encryption"])).decode()
    logging.info("[*] Decrypted: {}".format(decrypted_msg))
    
    conn.close()

def run(addr, port, msg):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()

        logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))

        conn_handle = threading.Thread(target=handler, args=(conn,msg,))
        conn_handle.start()
        conn_handle.join()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-m", "--message", metavar="<message>", help="Message", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port, args.message)

if __name__ == "__main__":
    main()
