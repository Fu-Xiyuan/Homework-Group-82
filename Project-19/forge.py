from ecc import S256Point,G,N,Signature
from random import randint


def test():
    GENESIS_BLOCK_PUBKEY = '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f'
    point = S256Point.parse(bytes.fromhex(GENESIS_BLOCK_PUBKEY))
    u = randint(0, N)
    v = randint(0, N)
    r = (u * G + v * point).x.num % N
    s = r * pow(v, N - 2, N) % N
    z = u * s % N
    sig = Signature(r, s)
    assert point.verify(z, sig) is True
    print("消息哈希值 : ", z)
    print('签名值 :', sig)


test()
