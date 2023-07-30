import hashlib


def gen_transactions(num):
    transactions = []
    for i in range(num):
        x = 'transaction'+str(i)
        transactions.append(x)
    return transactions


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


def merkle_audit_paths(m, transactions):
    length = len(transactions)
    if length <= 1:
        return []
    k = 1
    while not (k < length <= 2 * k):
        k = 2 * k
    path = []
    if m < k:
        left = merkle_audit_paths(m, transactions[0:k])
        right = merkle_tree_hash(transactions[k:length])
        path = path + left
        path.append(right)
    else:
        left = merkle_audit_paths(m-k, transactions[k:length])
        right = merkle_tree_hash(transactions[0:k])
        path = path + left
        path.append(right)
    return path


def path_proof(element, root_hash, path):
    flag = 0
    all_res = []

    sha = hashlib.sha256()
    sha.update(bytes(0x00) + element.encode())
    all_res.append(sha.hexdigest())

    hash_num = len(path)
    for j in range(hash_num):
        for i in range(len(all_res)):
            x = all_res[i]
            temp1 = str(0x01) + x + path[j]
            temp2 = str(0x01) + path[j] + x
            sha1 = hashlib.sha256()
            sha2 = hashlib.sha256()
            sha1.update(temp1.encode())
            all_res.append(sha1.hexdigest())
            sha2.update(temp2.encode())
            all_res.append(sha2.hexdigest())
    # print(all_res)
    if root_hash in all_res:
        flag = 1
    return flag


def in_exclusion_proof(element, root_hash, transaction_set):
    flag = 0
    for i in range(len(transaction_set)):
        path = merkle_audit_paths(i, transaction_set)
        flag += path_proof(element, root_hash, path)
    if flag == 1:
        print(element, "inclusion")
    else:
        print(element, "exclusion")


transaction_set = gen_transactions(10)
root = merkle_tree_hash(transaction_set)
test_element = ['transaction1', 'transaction2','transaction4', 'transaction8', 'transaction12', 'transaction16']
for i in range(len(test_element)):
    in_exclusion_proof(test_element[i], root, transaction_set)
