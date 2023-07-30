import socket
import sys
from Crypto.PublicKey import RSA
import ast
import hashlib
from Crypto.Cipher import PKCS1_OAEP
import binascii


def rsa_encrypt(data, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(data)
    return ciphertext


def rsa_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    data = cipher.decrypt(ciphertext)
    return data


def trans(da):
    public_key_str = ast.literal_eval(da)[2:-1].decode('utf-8')
    public_key_bytes = binascii.a2b_base64(''.join(public_key_str.strip().split('\n')[1:-1]))
    return public_key_bytes


ports = {"Trusted-issuer": 65000, "Alice": 65001, "Bob": 65002, "CA": 65003}


private_key = RSA.generate(2048).export_key()
public_key = RSA.import_key(private_key).publickey().export_key()
HOST = '127.0.0.1'
PORT = 65003
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((HOST, PORT))
except Exception as e:
    print('Server not found or not open')
    sys.exit()
while True:
    print("将公钥发送给 CA ...")
    c = "Bob@"+str(public_key)
    s.sendall(c.encode())
    data = s.recv(4096)
    data = data.decode()
    print('Received:', data)
    if data.lower() == 'success':
        break
s.close()

public_key_list = {}
HOST = ''
PORT = 65002
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT)) # 绑定socket
s.listen(1) # 开始监听客户端连接
print('Listening on port:', PORT)
conn, addr = s.accept()
print('Connected by', addr)
data = conn.recv(4096).decode()
conn.sendall("success".encode())
s.close()
da = data.split('@')
i = 0
while i < (len(da)-1):
    public_key_list.setdefault(da[i], trans(da[i+1]))
    i = i + 2
print(public_key_list)


while input('开始验证输入y:') == 'y':
    HOST = '127.0.0.1'
    PORT = ports['Trusted-issuer']
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        print('Server not found or not open')
        break
    while True:
        print("告诉Trusted-issuer开始验证")
        c = "Bob@Alice@begin"
        ak = rsa_encrypt(c.encode(), public_key_list['Trusted-issuer'])
        s.sendall(ak)
        data = s.recv(4096)
        da = rsa_decrypt(data, private_key).decode()
        print('Received:', da)
        if da.lower() == 'success':
            break
    s.close()

    HOST = ''
    PORT = 65002
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))  # 绑定socket
    s.listen(1)  # 开始监听客户端连接
    print('Listening on port:', PORT)
    conn, addr = s.accept()
    print('Connected by', addr)
    data = conn.recv(4096)
    da = rsa_decrypt(data, private_key).decode()
    dada = rsa_encrypt('success'.encode(), public_key_list['Alice'])
    conn.sendall(dada)
    s.close()

    sl = da.split('@')
    f = sl[0]
    t = sl[1]
    p = sl[2]
    sig_c = sl[3]
    c_ = p
    d1 = 100
    for i in range(d1):
        sha = hashlib.sha256()
        sha.update(c_.encode())
        c_ = sha.hexdigest()
    print('p', p)
    print("sig_c",sig_c)
    print('d1', d1)
    print("c_", c_)
    if sig_c == c_:
        print('验证成功')
    else:
        print("验证失败")
