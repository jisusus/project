import socket
import argparse
import logging
import json
import base64

def init_msg(conn):
    smsg = {}
    smsg["opcode"] = 0
    smsg["type"] = "DH"
    
    sjs = json.dumps(smsg)
    logging.debug("sjs: {}".format(sjs))
    
    sbytes = sjs.encode("ascii")
    logging.debug("sbytes: {}".format(sbytes))

    conn.send(sbytes)
    logging.info("[*] Sent: {}".format(sjs))

def mod(a,n):
    return a%n

def find_d(n):
    n = n-1
    while n % 2 == 0:
        n = n//2
    return n

def is_prime(n):
    if n == 2:
        return True
    elif (n == 1) or (n%2) == 0:
        return False
    else:
        a_list = [2,7,61]
        d = find_d(n)
        for a in a_list:
            if a >= n:
                break
            x1 = mod(a**d, n)
            if x1 in [1,n-1] :
                continue
            else:
                d_power = d
                x = x1
                while d_power <= n-1:
                    d_power *= 2
                    x = mod(x**2,n)
                    if x == n-1:
                        break
                else:
                    return False
        return True

def is_gen(g,n):
    x = g
    for _ in range(n-2):
        if (mod(x,n) == 1):
            return False
        else:
            x = mod(x*g,n)
    else:
        return True

def recieve_msg(conn):
    rbytes = conn.recv(1024)
    logging.debug("rbytes: {}".format(rbytes))

    rjs = rbytes.decode("ascii")
    logging.debug("rjs: {}".format(rjs))

    rmsg = json.loads(rjs)
    logging.info("rmsg: {}".format(rmsg))

def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    init_msg(conn)
    recieve_msg(conn)

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
