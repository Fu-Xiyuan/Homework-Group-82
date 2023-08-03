import random
import secrets

from ecdsa import SECP256k1, SigningKey
import hashlib


def bytes2int(seq):
    length = len(seq)
    st = ''
    for i in range(length):
        x = seq[i]
        st = st + bin(x)[2:].zfill(8)
    res = int(st, 2)
    return res


class ECMH:
    def __init__(self, curve=SECP256k1):
        self.curve = curve
        self.infinity = curve.generator * 0
        self.counts = {}

    def add(self, msg):
        h = hashlib.sha256(msg.encode()).digest()
        if h in self.counts:
            self.counts[h] += 1
        else:
            self.counts[h] = 1

    def remove(self, msg):
        h = hashlib.sha256(msg.encode()).digest()
        if h in self.counts:
            if self.counts[h] > 1:
                self.counts[h] -= 1
            else:
                del self.counts[h]

    def digest(self, k):
        sorted_hashes = sorted(self.counts.keys(), key=lambda h: -self.counts[h])
        sk = SigningKey.from_secret_exponent(k, curve=self.curve)
        h = hashlib.sha256()
        p = self.infinity
        for h_i in sorted_hashes:
            for _ in range(self.counts[h_i]):
                p = p + (bytes2int(sk.sign(h_i)) * self.curve.generator)
        h.update(p.x().to_bytes(32, 'big'))
        return h.digest()


def test():
    msgs = ['hello', 'world', 'hello', 'foo', 'bar', 'hello', 'world', 'hello', 'world', 'foo']
    print('消息列表 :\n', msgs)
    k = int.from_bytes(b'123456789', 'big')
    print('私钥值 :\n', k)

    ecmh = ECMH()
    for msg in msgs:
        ecmh.add(msg)
    hash_value = ecmh.digest(k)
    print('结果哈希 :\n', hash_value.hex())
    # 随机删除一个消息
    n = len(msgs)
    x = random.randint(0, n-1)
    print('删除', msgs[x])
    ecmh.remove(msgs[x])
    hash_value = ecmh.digest(k)
    print('结果哈希 :\n', hash_value.hex())
    # 随机添加一个消息
    x = secrets.token_hex(4)
    print('添加', x)
    ecmh.add(x)
    hash_value = ecmh.digest(k)
    print('结果哈希 :\n', hash_value.hex())


test()
