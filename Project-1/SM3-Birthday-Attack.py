import secrets
import SM3
import time


def birthday_attack():
    # 创建一个字典，存储对应的消息和hash值
    hash_table = {}
    attack_size = [1, 2, 4, 8, 9]
    for i in range(len(attack_size)):
        stat_time = time.time()
        while True:
            # 随机生成消息
            message = secrets.token_hex(16)
            # 计算对应的hash值
            same_value = SM3.sm3(message)[:attack_size[i]]
            # 如果该hash值存在且对应消息值不同，那么碰撞找到，结束
            if same_value in hash_table and message != hash_table[same_value]:
                end_time = time.time()
                use_time = end_time - stat_time
                print("Message 1:", message, "Hash Value :", SM3.sm3(message))
                print("Message 2:", hash_table[same_value], "Hash Value :", SM3.sm3(hash_table[same_value]))
                print("Same Value :", same_value)
                print("Same Value Size :", attack_size[i]*4, "bits")
                print("Time Use :", use_time)
                print("--------------------------------------------------------------------")
                break
            else:
                hash_table[same_value] = message


birthday_attack()
