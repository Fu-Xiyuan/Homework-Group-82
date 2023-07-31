import hashlib
import hmac
import secrets
import numpy as np
import random
import time


def kdf(master_seed, num_seeds):
    seed_len = len(master_seed)
    hash_algo = hashlib.sha256
    hmac_obj = hmac.new(master_seed, None, hash_algo)
    seeds = []
    for i in range(num_seeds):
        hmac_obj.update(bytes([i]))
        digest = hmac_obj.hexdigest()
        seed = digest[0:seed_len]
        seeds.append(seed)

    return seeds


def pl_accum(hash1, hash2, hash3, eps=1e-6, max_iters=1000):
    data = b"".join([bytes.fromhex(h) for h in [hash1, hash2, hash3]])
    x = np.frombuffer(data, dtype=np.float32)
    f_val = np.sum(x)
    for i in range(max_iters):
        grad = np.ones(3)
        alpha = np.sqrt(i + 1)
        x = x - (1 / alpha) * grad.reshape(-1, 1) * np.ones_like(x)
        f_val_new = np.sum(x)
        if abs(f_val_new - f_val) < eps:
            break
        f_val = f_val_new
    return x.tobytes()


def shuffle(hash1, hash2, hash3, seed):
    hashes = [hash1, hash2, hash3]
    random.seed(seed)
    random.shuffle(hashes)
    return hashes


def hash_chains(seed, n):
    chains = []
    x = seed
    chains.append(x)
    for i in range(n):
        sha = hashlib.sha256()
        sha.update(x.encode())
        x = sha.hexdigest()
        chains.append(x)

    return chains


def merkle_tree_hash(transactions):
    length = len(transactions)
    if length == 0:
        return None
    if length == 1:
        h = hashlib.sha256()
        h.update(bytes(0x00) + transactions[0].encode('utf-8'))
        return h.hexdigest()
    k = 1
    while not (k < length <= 2 * k):
        k = 2 * k
    left = merkle_tree_hash(transactions[0:k])
    right = merkle_tree_hash(transactions[k:length])
    data = str(0x01) + left + right
    sha = hashlib.sha256()
    sha.update(data.encode())
    return sha.hexdigest()


def generalizing_hash_chains():
    master_key = secrets.token_hex(16)
    seed_set = kdf(master_key.encode(), 8)

    seed_d = seed_set[0]
    seed_1 = seed_set[1]
    seed_2 = seed_set[2]
    seed_3 = seed_set[3]
    salt_a = seed_set[4]
    salt_b = seed_set[5]
    salt_c = seed_set[6]
    shuffle_seed = seed_set[7]

    seed_d_chain = hash_chains(seed_d, 9)
    seed_1_chain = hash_chains(seed_1, 3)
    seed_2_chain = hash_chains(seed_2, 3)
    seed_3_chain = hash_chains(seed_3, 3)

    a = pl_accum(seed_3_chain[3], seed_2_chain[1], seed_1_chain[2])
    b = pl_accum(seed_3_chain[3], seed_2_chain[0], seed_1_chain[3])
    c = pl_accum(seed_3_chain[2], seed_2_chain[3], seed_1_chain[3])

    h = hashlib.sha256()

    h.update(salt_a.encode() + a)
    A = h.hexdigest()
    h.update(salt_b.encode() + b)
    B = h.hexdigest()
    h.update(salt_c.encode() + c)
    C = h.hexdigest()

    leaf_list = shuffle(A, B, C, shuffle_seed)
    leaf_list.append(seed_d_chain[-1])

    root = merkle_tree_hash(leaf_list)

    return root


print('开始执行')
s = time.time()
for i in range(10):
    print('root :', generalizing_hash_chains())
e = time.time()
print('执行完成')
print('执行 10 次用时 :', e - s, '秒')
