import socket
import argparse
import logging
import json
import random
import base64

def is_prime_number(x):
    for i in range(2, x):
        if x % i == 0:
            return False
    return True

def verify_p_q(data):
    p = data["parameter"]["p"]
    q = data["parameter"]["q"]

    # p와 q가 소수인지 확인
    if not (is_prime_number(p) and is_prime_number(q)):
        print("p 또는 q가 소수가 아닙니다.")
        return False
    else: print("p q는 소수가 맞습니다.")

def verify_RSA_Keypair(data):
    p = data["parameter"]["p"]
    q = data["parameter"]["q"]
    public_key = data["public"]
    private_key = data["private"]

    # 공개 키와 개인 키 검증
    n = p * q
    e = public_key
    phi = (p - 1) * (q - 1)
    d = private_key

    # (e * d) % phi = 1을 만족하는지 확인
    if (e * d) % phi != 1:
        print("RSA 키 쌍이 올바르지 않습니다.")
    else:
        print("RSA 키 쌍이 유효합니다.")
        print(f"Public Key: {public_key}, Private Key: {private_key}")

def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    random.seed(None)

    #opcode랑 type 보내기
    smsg = {} 
    smsg["opcode"] = 0
    smsg["type"] = "RSAKey"
    logging.debug("smsg: {}".format(smsg))

    sjs = json.dumps(smsg)
    logging.debug("sjs: {}".format(sjs))

    sbytes = sjs.encode("ascii")
    logging.debug("sbytes: {}".format(sbytes))

    conn.send(sbytes)
    logging.info("[*] Sent: {}".format(sjs))


    # RSA Key pair 받아오기
    rbytes = conn.recv(1024)
    logging.debug("rbytes: {}".format(rbytes))

    rjs = rbytes.decode("ascii")
    logging.debug("rjs: {}".format(rjs))

    rmsg = json.loads(rjs)
    logging.debug("rmsg: {}".format(rmsg))

    logging.info("[*] Received: {}".format(rjs))
    logging.info(" - opcode: {}".format(rmsg["opcode"]))
    logging.info(" - type: {}".format(rmsg["type"]))
    logging.info(" - private: {}".format(rmsg["private"]))
    logging.info(" - public: {}".format(rmsg["public"]))
    logging.info(" - parameter: {}".format(rmsg["parameter"]))
    logging.info("   - p: {}".format(rmsg["parameter"]["p"]))
    logging.info("   - q: {}".format(rmsg["parameter"]["q"]))

    verify_p_q(rmsg)

    verify_RSA_Keypair(rmsg)

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
