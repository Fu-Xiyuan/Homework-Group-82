import socket
import sys
from Crypto.PublicKey import RSA
import ast
import numpy as np
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import binascii


def info(pkl):
    res = ''
    x = list(pkl.items())
    for i in range(len(x)):
        a = x[i][0]
        b = x[i][1]
        res = res + str(a) + '@' + str(b) + '@'
    return res


def trans(da):
    public_key_str = ast.literal_eval(da)[2:-1].decode('utf-8')
    public_key_bytes = binascii.a2b_base64(''.join(public_key_str.strip().split('\n')[1:-1]))
    return public_key_bytes


ports = {"Trusted-issuer": 65000, "Alice": 65001, "Bob": 65002, "CA": 65003}
public_key_list = {"Trusted-issuer": 60000, "Alice": 60001, "Bob": 60002, "CA": 60003}

private_key = RSA.generate(2048).export_key()
public_key = RSA.import_key(private_key).publickey().export_key()
public_key_list['CA'] = public_key

HOST = ''
PORT = 65003
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT)) # 绑定socket
i = 0
while True:
    s.listen(1) # 开始监听客户端连接
    print('Listening on port:', PORT)
    conn, addr = s.accept()
    print('Connected by', addr)
    data = conn.recv(4096).decode()
    da = data.split("@")
    print('Received:', da[1], "from:", da[0])
    public_key_list[da[0]] = da[1]
    i = i + 1
    conn.sendall('success'.encode())
    if i == 3:
        break
print(public_key_list)
s.close()

li = ['Alice', 'Bob', 'Trusted-issuer']
for i in range(3):
    HOST = '127.0.0.1'
    PORT = ports[li[i]]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        print('Server not found or not open')
        sys.exit()
    while True:
        print("将全部公钥信息告知给 {} ...".format(li[i]))
        c = info(public_key_list)
        s.sendall(c.encode())
        data = s.recv(4096)
        data = data.decode()
        print('Received:', data)
        if data.lower() == 'success':
            break
    s.close()
print(public_key_list)
