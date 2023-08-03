import hashlib
import random

# 定义椭圆曲线参数
p = 2**256 - 2**32 - 977
a = 0
b = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337


# 定义Schnorr签名函数
def schnorr_sign(m, x):
    k = random.randint(1, n-1)
    R = (k * Gx, k * Gy)
    e = int(hashlib.sha256(str(R[0]).encode() + m).hexdigest(), 16)
    s = (k + x * e) % n
    return R, s


# 定义Schnorr Batch签名验证函数
def schnorr_batch_verification(msg_list, x):
    r_0 = 0
    r_1 = 0
    e_0 = 0
    e_1 = 0
    ss = 0
    for msg in msg_list:
        r, s = schnorr_sign(msg.encode(), x)
        e = int(hashlib.sha256(str(r[0]).encode() + msg.encode()).hexdigest(), 16)
        e_0 += e * x * Gx
        e_1 += e * x * Gy
        ss += s
        r_0 += r[0]
        r_1 += r[1]
    E = (e_0 % n, e_1 % n)
    R = (r_0 % n, r_1 % n)
    S = ss % n
    a = (S * Gx % n, S * Gy % n)
    print(a)
    b = ((R[0] + E[0]) % n, (R[1] + E[1]) % n)
    print(b)
    if a == b:
        print('success')
    return R, S


# 测试代码
msg_list = ["hello", "world", "schnorr", "batch"]
x = random.randint(1, n-1)
sig = schnorr_batch_verification(msg_list, x)
print(sig)
