import hashlib
import random
import secrets

from Crypto.Util.number import inverse


# ECDSA parameters
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
q = 0x4000000000000000000020108A2E0CC0D99F8A5EF
x = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
Gx = 0x79AEE090DB05EC252D5CB4452F356BE198A4FF96F
Gy = 0x782E29634DDC9A31EF40386E896BAA18B53AFA5A3
d = 9876543210123456789
P = (d * Gx % n, d * Gy % n)


def hash_func(msg):
    Hash = hashlib.sha256()
    Hash.update(msg)
    res = Hash.digest()
    return res


def sign(msg, krand=1):
    if krand == 0:
        k = 10000
    elif krand == 2:
        k = 9876543210123456789
    else:
        k = random.randint(1, n - 1)
    R = (k * Gx % n, k * Gy % n)
    r = R[0] % n
    e = int(hash_func(msg).hex(), 16) % n
    s = inverse(k, n) * (e + d * r) % n
    return r, s


def verify(sig, m):
    r = sig[0]
    s = sig[1]
    e = int(hash_func(m).hex(), 16) % n
    w = inverse(s, n)
    r_ = (e * w * Gx + r * w * P[0]) % n
    s_ = (e * w * Gy + r * w * P[1]) % n
    sig_ = (r_, s_)
    if sig[0] == sig_[0]:
        res = 1
        print("合法签名!")
    else:
        res = 2
        print("非法签名!")

    return res


def leaking_k_leaking_d_test():
    k = 10000
    m = secrets.token_bytes(16)
    e = int(hash_func(m).hex(), 16)
    sig = sign(m, 0)
    r = sig[0]
    s = sig[1]
    dd = (inverse(r, n) * (s * k - e)) % n
    if dd == d:
        print('恢复出私钥 : ', dd)
    else:
        print('恢复私钥失败')


def reusing_k_leaking_d_test():
    m1 = secrets.token_bytes(16)
    m2 = secrets.token_bytes(16)
    sig1 = sign(m1, 0)
    sig2 = sign(m2, 0)
    e1 = int(hash_func(m1).hex(), 16)
    e2 = int(hash_func(m2).hex(), 16)

    r1 = sig1[0]
    s1 = sig1[1]
    r2 = sig2[0]
    s2 = sig2[1]

    k = inverse(s1 * inverse(r1, n) - s2 * inverse(r2, n), n) * (e1 * inverse(r1, n) - e2 * inverse(r2, n)) % n

    dd = (inverse(r1, n) * (s1 * k - e1)) % n
    if dd == d:
        print('恢复出私钥 : ', dd)
    else:
        print('恢复私钥失败')


def same_d_k_leaking_d_test():
    m = secrets.token_bytes(16)
    e = int(hash_func(m).hex(), 16)
    sig = sign(m, 2)
    r = sig[0]
    s = sig[1]

    dd = inverse(s - r, n) * e % n
    if dd == d:
        print('恢复出私钥 : ', dd)
    else:
        print('恢复私钥失败')


leaking_k_leaking_d_test()
reusing_k_leaking_d_test()
same_d_k_leaking_d_test()
