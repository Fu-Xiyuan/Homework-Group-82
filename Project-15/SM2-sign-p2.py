import random
import socket
import sys
from Crypto.Util.number import inverse
from Crypto.PublicKey import RSA
import ast
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


while True:
    # 网络端口
    ports = {"p1": 65000, "p2": 65001}
    # SM2椭圆曲线参数
    a = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)
    b = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)
    p = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
    Gx = int('32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7', 16)
    Gy = int('bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0', 16)
    n = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)
    # p2 公钥私钥
    public_key = b'-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArQaja2h6SOOmBa0Nk7M3\n2ndvqEJ+mULShbYFH1xnalYX7MKZKas+ByHdL3FfBBQrYxLTDy0JHA4NdqWPngqE\nX0fmSZHGbBF013yglH+Nsfl0bVgIVygKFqTv8jBJaYRaHmeGHy/cmQhMiUhxZSdk\nTgx4thtpO+HJkhymcuWrXhJjIHS5IqIuv2ZxTsDjsARb4RoC9UlCGCbM+L372YsT\nQfTasrZNPwFx32VGo+lpgVgtzUl0yF+55veuOXu1Z/dAJ7G9Y/6V2TvUZDTqAHhS\ng8noEn9r5olsWvKh42fihBWzFOqoEwt4h+Ogh7vuKhrrmlSlxPJE//2uaQeMxciS\nBiMvHQsc7PQFqFUw4He7uIftGQwla/aY4nHJotZ30bj5vjE2cPm8U4+ucXw7DN4u\nnBipt3SPkmKHLshaaAs9kHmsNM/YduES1s/EZ76IvGQKNUz1YfDNmfkCptmcFhiU\nfp9gPLBn/W+54kHmKaYN6qBb89DNas1AnN14BHRng50QfWtGrqmOGXwvlDD+Bum0\nm6XykGnWnJg/q5plKIvgX/tDLNJBM7+luZWv4kD84/U+MIFHIAsnmzEhcwKl/C3r\nIqbkB1v0vdfN+xoW7xnPEUIk3heXh3SExqHuJ6jk4goBp82ohBVsDADDSfgvLKxH\npaMZPQDMWu103pvz+2HAO6UCAwEAAQ==\n-----END PUBLIC KEY-----'
    private_key = b'-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----'

    # p1 公钥
    public_key_p1 = b'-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAw7vDnie7auwUHxRpH3zw\nYCCwEdKuZeryQY15s7r0/15j+sr3oB+AZ8ayPX6bZcoQexHAv95jB8jP3rjyIDvT\n6/Y31g8eL1B0tii5kBEsjQ9/72fN6oRbQhi52PoWbSBcSum/AnMjS446jgCpJ2Fv\nr31Uw74Kbzn3WknNu6k4Nq4CkFjjyRo7T5v83M43i9jmLPa6xph2d8LojXkOtKfm\nGAm6B2vzQjyvAkPdvmMfJALmcKNGiwPJVa8NnlFEY54oCTVXKhWiFlFghgPrMHXO\nRrjEx7TRZl/cfN2KOZAFRT+nI3TmQzFdrE9Z7jNSusYrnlrubtK8ZVEj+nJgP3RA\n3VjSKrfGusLGfpDZhXyXNM7vR18fbkWjb61GGHaY1fShZNMN1wiNMKKNz+uFbKJm\nd9+g8qDeRC0dlrh50l6Mk1jzvi40uBWtIt4U2G36ZGF4sCIKTrTLXtLz0pMLJgKy\nuznpIZgn5mX/KNS13wTEM0Hd4Fu+COjz3iv6NxrQi/vkuP2fqFy2kFSr0BhxezRf\nu664WQaEagX0zvzIT/6XTm9EitsoSHQV/LAYeq563cVYaZZzqPkbxrP3I/vDwecd\n32fpqMPe+o1jYjHw7XheSKpQ3B1X1nZzHsRypAQzBut7hm62Wc9A5uUYUBhSLaN4\nISjdrFDoZcY0wAm28NM/oXMCAwEAAQ==\n-----END PUBLIC KEY-----'

    # 等待 P1
    HOST = ''
    PORT = ports['p2']
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    print('Listening on port:', PORT)
    conn, addr = s.accept()
    print('Connected by', addr)
    data = conn.recv(4096)
    dat = rsa_decrypt(data, private_key).decode()
    print('Received:', dat)
    da = rsa_encrypt('success'.encode(), public_key_p1)
    conn.sendall(da)
    s.close()

    # (2)
    P1 = int(dat)
    d2 = random.randint(1, n - 1)
    d2_inv = inverse(d2, n)
    P = d2_inv * P1 - Gx

    # 等待 Q1, e
    HOST = ''
    PORT = ports['p2']
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    print('Listening on port:', PORT)
    conn, addr = s.accept()
    print('Connected by', addr)
    data = conn.recv(4096)
    dat = rsa_decrypt(data, private_key).decode()
    print('Received:', dat)
    da = rsa_encrypt('success'.encode(), public_key_p1)
    conn.sendall(da)
    s.close()

    # (4)
    li = dat.split('@@@')
    Q1 = int(li[0])
    e = int(li[1], 16)
    k2 = random.randint(1, n - 1)
    Q2 = k2 * Gx
    k3 = random.randint(1, n - 1)
    x1 = k3 * Q1 + Q2
    r = (x1 + e) % n
    s2 = (d2 * k3) % n
    s3 = (d2 * (r + k2)) % n

    # 发送 r, s2, s3
    HOST = '127.0.0.1'
    PORT = ports['p1']
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        print('Server not found or not open')
        sys.exit()
    while True:
        print("发送 r :", r)
        print("发送 s2 :", s2)
        print("发送 s3 :", s3)

        c = str(r) + "@@@" + str(s2) + "@@@" + str(s3)
        cc = rsa_encrypt(c.encode(), public_key_p1)
        s.sendall(cc)
        data = s.recv(4096)
        da = rsa_decrypt(data, private_key).decode()
        print('Received:', da)
        if da.lower() == 'success':
            break
    s.close()

    # finish


