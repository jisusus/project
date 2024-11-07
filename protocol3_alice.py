import socket
import argparse
import logging
import json
import random
import base64
from Crypto.Cipher import AES

BLOCK_SIZE = 16

def is_generator(p, g):
    a = set()
    for i in range(1, p):
        a.add((g ** i) % p)
    
    if len(a) == p-1:
        return True
    else:
        return False

def is_prime_number(x):
    for i in range(2, x):
        if x % i == 0:
            return False
    return True

def generate_DH_keypair(p, g):
    b = random.randrange(1, p)
    public_key = (g ** b) % p
    
    return b, public_key

def encrypt(key, msg):
    pad = BLOCK_SIZE - len(msg)
    msg = msg + pad * chr(pad)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(msg.encode())

def decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(encrypted)

def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    random.seed(None)

    smsg = {} 
    smsg["opcode"] = 0
    smsg["type"] = "DH"
    logging.debug("smsg: {}".format(smsg))
    
    sjs = json.dumps(smsg)
    logging.debug("sjs: {}".format(sjs))

    sbytes = sjs.encode("ascii")
    logging.debug("sbytes: {}".format(sbytes))

    conn.send(sbytes)
    
    rbytes = conn.recv(1024)
    logging.debug("rbytes: {}".format(rbytes))

    rjs = rbytes.decode("ascii")
    logging.debug("rjs: {}".format(rjs))

    rmsg = json.loads(rjs)
    logging.debug("rmsg: {}".format(rmsg))

    logging.info("[*] Received: {}".format(rjs))
    logging.info(" - opcode: {}".format(rmsg["opcode"]))
    logging.info(" - type: {}".format(rmsg["type"]))
    logging.info(" - public: {}".format(rmsg["public"]))
    logging.info(" - parameter: {}".format(rmsg["parameter"]))
    
    p = rmsg["parameter"]["p"]
    g = rmsg["parameter"]["g"]
    
    if is_prime_number(p) == True:
        print("p는 소수입니다")
    else:
        print("p는 소수가 아닙니다")
        
    if is_generator(p, g) == True:
        print("g는 올바른 Generator입니다")
    else:
        print("g는 올바른 Generator가 아닙니다")
    
    a, alice_keypair = generate_DH_keypair(p, g)
    DH_shared_secret = (rmsg["public"] ** a) % p
    DH_shared_secret.to_bytes(2, byteorder = "big")
    AES_key = DH_shared_secret * 16
    AES_key = DH_shared_secret.to_bytes(32, byteorder='big')
    
    smsg_1 = {}
    smsg_1["opcode"] = 1
    smsg_1["type"] = "DH"
    smsg_1["public"] = alice_keypair
    logging.debug("smsg: {}".format(smsg_1))

    sjs_1 = json.dumps(smsg_1)
    logging.debug("sjs: {}".format(sjs_1))

    sbytes_1 = sjs_1.encode("ascii")
    logging.debug("sbytes: {}".format(sbytes_1))

    conn.send(sbytes_1)
    
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
    
    decrypted = decrypt(AES_key, base64.b64decode(rmsg_2["encryption"])).decode()
    decrypted = decrypted[0:-ord(decrypted[-1])]
    logging.info("[*] Decrypted: {}".format(decrypted))
    
    smsg_2 = {}
    smsg_2["opcode"] = 2
    smsg_2["type"] = "AES"
    encrypted = encrypt(AES_key, decrypted)
    
    smsg_2["encryption"] = base64.b64encode(encrypted).decode()
    logging.debug("smsg: {}".format(smsg_2))

    sjs_2 = json.dumps(smsg_2)
    logging.debug("sjs: {}".format(sjs_2))

    sbytes_2 = sjs_2.encode("ascii")
    logging.debug("sbytes: {}".format(sbytes_2))

    conn.send(sbytes_2)
    
    conn.close()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
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