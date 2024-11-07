import socket
import threading
import argparse
import logging
import json
import random
import base64

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

def gen_prime(bool):
    n = random.randint(400,500)
    while is_prime(n) != bool:
        n = random.randint(400,500)
    return n

def is_gen(g,n):
    x = g
    for _ in range(n-2):
        if (mod(x,n) == 1):
            return False
        else:
            x = mod(x*g,n)
    else:
        return True

def gen_gen(bool,n):
    g = random.randint(1,n-1)
    while is_gen(g,n) != bool:
        g = random.randint(1,n-1)
    return g

def DH_private(g,n):
    private = random.randint(1,n)
    return private

def public_to_base64(public):
    print(public)
    public = public.to_bytes(2,"big")
    public = base64.b64encode(public).decode('ascii')
    print(public)
    return public

def DH_sendkeys(public,p,g,conn):
    data = {
        "opcode": 1,
        "type": "DH",
        "public": public,
        "parameter": {"p": p, "g":g}
    }
    
    sjs = json.dumps(data)
    logging.debug("sjs: {}".format(sjs))
    
    sbytes = sjs.encode("ascii")
    logging.debug("sbytes: {}".format(sbytes))

    conn.send(sbytes)
    logging.info("[*] Sent: {}".format(sjs))

def handler(conn):
    rbytes = conn.recv(1024)
    logging.info("rbytes: {}".format(rbytes))

    rjs = rbytes.decode("ascii")
    logging.debug("rjs: {}".format(rjs))

    rmsg = json.loads(rjs)
    logging.debug("rmsg: {}".format(rmsg))

    logging.info("[*] Received: {}".format(rjs))
    logging.info(" - opcode: {}".format(rmsg["opcode"]))
    logging.info(" - type: {}".format(rmsg["type"]))
    
    p = gen_prime(random.choice([True,False]))
    g = gen_gen(random.choice([True,False]),p)
    
    private = DH_private(g,p)
    public = mod(g**private, p)
    public_b64 = public_to_base64(public)
    
    DH_sendkeys(public_b64,p,g,conn)

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

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="127.21.0.1")
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
