import random
import secrets
import socket
import sys
from Crypto.Util.number import inverse
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


while input('输入y开始 : ') == 'y':
    # 网络端口
    ports = {"p1": 65000, "p2": 65001}
    # SM2椭圆曲线参数
    a = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)
    b = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)
    p = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
    Gx = int('32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7', 16)
    Gy = int('bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0', 16)
    n = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)
    # p1 公钥私钥
    public_key = b'-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAw7vDnie7auwUHxRpH3zw\nYCCwEdKuZeryQY15s7r0/15j+sr3oB+AZ8ayPX6bZcoQexHAv95jB8jP3rjyIDvT\n6/Y31g8eL1B0tii5kBEsjQ9/72fN6oRbQhi52PoWbSBcSum/AnMjS446jgCpJ2Fv\nr31Uw74Kbzn3WknNu6k4Nq4CkFjjyRo7T5v83M43i9jmLPa6xph2d8LojXkOtKfm\nGAm6B2vzQjyvAkPdvmMfJALmcKNGiwPJVa8NnlFEY54oCTVXKhWiFlFghgPrMHXO\nRrjEx7TRZl/cfN2KOZAFRT+nI3TmQzFdrE9Z7jNSusYrnlrubtK8ZVEj+nJgP3RA\n3VjSKrfGusLGfpDZhXyXNM7vR18fbkWjb61GGHaY1fShZNMN1wiNMKKNz+uFbKJm\nd9+g8qDeRC0dlrh50l6Mk1jzvi40uBWtIt4U2G36ZGF4sCIKTrTLXtLz0pMLJgKy\nuznpIZgn5mX/KNS13wTEM0Hd4Fu+COjz3iv6NxrQi/vkuP2fqFy2kFSr0BhxezRf\nu664WQaEagX0zvzIT/6XTm9EitsoSHQV/LAYeq563cVYaZZzqPkbxrP3I/vDwecd\n32fpqMPe+o1jYjHw7XheSKpQ3B1X1nZzHsRypAQzBut7hm62Wc9A5uUYUBhSLaN4\nISjdrFDoZcY0wAm28NM/oXMCAwEAAQ==\n-----END PUBLIC KEY-----'
    private_key = b'-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----'
    public_key_p2 = b'-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArQaja2h6SOOmBa0Nk7M3\n2ndvqEJ+mULShbYFH1xnalYX7MKZKas+ByHdL3FfBBQrYxLTDy0JHA4NdqWPngqE\nX0fmSZHGbBF013yglH+Nsfl0bVgIVygKFqTv8jBJaYRaHmeGHy/cmQhMiUhxZSdk\nTgx4thtpO+HJkhymcuWrXhJjIHS5IqIuv2ZxTsDjsARb4RoC9UlCGCbM+L372YsT\nQfTasrZNPwFx32VGo+lpgVgtzUl0yF+55veuOXu1Z/dAJ7G9Y/6V2TvUZDTqAHhS\ng8noEn9r5olsWvKh42fihBWzFOqoEwt4h+Ogh7vuKhrrmlSlxPJE//2uaQeMxciS\nBiMvHQsc7PQFqFUw4He7uIftGQwla/aY4nHJotZ30bj5vjE2cPm8U4+ucXw7DN4u\nnBipt3SPkmKHLshaaAs9kHmsNM/YduES1s/EZ76IvGQKNUz1YfDNmfkCptmcFhiU\nfp9gPLBn/W+54kHmKaYN6qBb89DNas1AnN14BHRng50QfWtGrqmOGXwvlDD+Bum0\nm6XykGnWnJg/q5plKIvgX/tDLNJBM7+luZWv4kD84/U+MIFHIAsnmzEhcwKl/C3r\nIqbkB1v0vdfN+xoW7xnPEUIk3heXh3SExqHuJ6jk4goBp82ohBVsDADDSfgvLKxH\npaMZPQDMWu103pvz+2HAO6UCAwEAAQ==\n-----END PUBLIC KEY-----'
    # （1）
    d1 = random.randint(1, n - 1)
    d1_inverse = inverse(d1, n)
    P1 = d1_inverse * Gx

    # 发送 P1
    HOST = '127.0.0.1'
    PORT = ports['p2']
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        print('Server not found or not open')
        sys.exit()
    while True:
        print('发送 P1 :', P1)
        c = rsa_encrypt(str(P1).encode(), public_key_p2)
        s.sendall(c)
        data = s.recv(4096)
        da = rsa_decrypt(data, private_key).decode()
        print('Received:', da)
        if da.lower() == 'success':
            break
    s.close()

    # (3)
    Z = secrets.token_hex(16)
    M = secrets.token_hex(16)
    M_ = Z + M
    Hash = hashlib.sha256()
    Hash.update(M.encode())
    e = Hash.hexdigest()
    k1 = random.randint(1, n - 1)
    Q1 = k1 * Gx

    # 发送 Q1, e
    HOST = '127.0.0.1'
    PORT = ports['p2']
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        print('Server not found or not open')
        sys.exit()
    while True:
        print('发送 Q1 :', Q1)
        print('发送 e :', e)
        cc = str(Q1) + '@@@' + e
        c = rsa_encrypt(cc.encode(), public_key_p2)
        s.sendall(c)
        data = s.recv(4096)
        da = rsa_decrypt(data, private_key).decode()
        print('Received:', da)
        if da.lower() == 'success':
            break
    s.close()

    # 等待 r, s2, s3
    HOST = ''
    PORT = ports['p1']
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    print('Listening on port:', PORT)
    conn, addr = s.accept()
    print('Connected by', addr)
    data = conn.recv(4096)
    dat = rsa_decrypt(data, private_key).decode()
    print('Received:', dat)
    da = rsa_encrypt('success'.encode(), public_key_p2)
    conn.sendall(da)

    # （5）
    li = dat.split('@@@')
    r = int(li[0])
    s2 = int(li[1])
    s3 = int(li[2])
    s = ((d1 * k1) * s2 + d1 * s3 - r) % n
    if s != 0 or s != n - r:
        sign = (r, s)
        print(sign)

    # finish

