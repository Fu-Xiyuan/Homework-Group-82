import hashlib
import hmac
import random
import time

# ECDSA parameters
# a = p - 3
# b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
q = 0x4000000000000000000020108A2E0CC0D99F8A5EF
x = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
Gx = 0x79AEE090DB05EC252D5CB4452F356BE198A4FF96F
Gy = 0x782E29634DDC9A31EF40386E896BAA18B53AFA5A3

qlen = 163
rlen = 168


def hash_func(msg):
    Hash = hashlib.sha256()
    Hash.update(msg)
    res = Hash.digest()
    return res


def hmac_sha256(key, msg):
    return hmac.new(key, msg, digestmod='sha256').digest()


def all2bits(everything):
    res = ''
    if isinstance(everything, int):
        res = bin(everything)[2:].zfill(168)
    elif isinstance(everything, bytes):
        mlen = len(everything)
        for i in range(mlen):
            m = bin(everything[i])[2:].zfill(8)
            res = m + res
    return res.encode()


def bits2int(b):
    b = b.hex()
    b = int(b, 16)
    b = all2bits(b)
    b = b.decode()
    blen = len(b)
    if qlen < blen:
        b = b[0:qlen]
    else:
        b = '0' * (qlen - blen) + b
    res = int(b, 2)
    return res


def int2octets(x):
    mlen = 21
    if x > q:
        x = x % q
    X = []
    xx = all2bits(x)
    for j in range(0, 168, 8):
        xxx = xx[j:j+8]
        X.append(int(xxx, 2))
    M = []
    for i in range(mlen):
        M.append(X[i])
    return bytes(M)


def bits2octets(b):
    b = b.hex()
    b = int(b, 16)
    b = all2bits(b)
    z1 = bits2int(b)
    z2 = z1 % q
    res = int2octets(z2)
    return res


def deterministic_k(msg):
    h1 = hash_func(msg)
    # print('h1', h1.hex())
    # xx = int2octets(x)
    # print("x", xx.hex())
    # print('h1', bits2octets(h1).hex())
    # print(int2octets(x).hex())
    V = b'\x01' * 32
    # print('V', V.hex())
    K = b'\x00' * 32
    # print('K', K.hex())
    K = hmac_sha256(K, V + b'\x00' + int2octets(x) + bits2octets(h1))
    # print('K', K.hex())
    V = hmac_sha256(K, V)
    # print('V', V.hex())
    K = hmac_sha256(K, V + b'\x01' + int2octets(x) + bits2octets(h1))
    # print('K', K.hex())
    V = hmac_sha256(K, V)
    # print('V', V.hex())
    flag = 3
    while True:
        T = b''
        tlen = 0
        while tlen < qlen:
            V = hmac_sha256(K, V)
            T = T + V
            # print('T', T.hex())
            tlen = len(T) * 8
        k = bits2int(T)
        # print('k', hex(k))
        # print(k - q)
        if 0 < k < q:
            break
        else:
            K = hmac_sha256(K, V + b'\x00')
            V = hmac_sha256(K, V)
            # print('K', K.hex())
            # print('V', V.hex())
        flag = flag - 1
        if flag == 0:
            break
    # print(flag)
    return k


def sign_deterministic(msg):

    hm = hash_func(msg)
    # print(hm.hex())
    h = bits2int(hm) % q
    # print(h)
    k = deterministic_k(msg)
    r = k * Gx % q
    s = int(((h + x * r) / k) % q)

    print('k', k)
    print('r', r)
    print('s', s)
    return r, s


st = time.time_ns()
for i in range(10000):
    a, b = sign_deterministic('sample'.encode())
et = time.time_ns()
print('完成 10000 次签名用时 :', (et-st)/1000000000, '秒')
print('完成 1 次签名用时 :', (et-st)/10000000000000, '秒')

