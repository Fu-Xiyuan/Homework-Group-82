import SM3
import secrets
import time


def hex2byte(msg):  # 16进制字符串转换成byte数组
    ml = len(msg)
    if ml % 2 != 0:
        msg = '0' + msg
    ml = int(len(msg) / 2)
    msg_byte = []
    for i in range(ml):
        msg_byte.append(int(msg[i * 2:i * 2 + 2], 16))
    return msg_byte


def padding(msg):
    len1 = len(msg)
    reserve1 = len1 % 64
    msg.append(0x80)
    reserve1 = reserve1 + 1
    # 56-64, add 64 byte
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64

    for i in range(reserve1, range_end):
        msg.append(0x00)

    bit_length = (len1) * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7 - i])
    return msg


def deal(msg):
    group_count = round(len(msg) / 64)

    B = []
    for i in range(0, group_count):
        B.append(msg[i * 64:(i + 1) * 64])
    return B


def byte2hex(msg):  # byte数组转换成16进制字符串
    ml = len(msg)
    hexstr = ""
    for i in range(ml):
        hexstr = hexstr + ('%02x' % msg[i])
    return hexstr


def len_ex_attach(message, hash_message):
    # 处理已知哈希值作为初始向量
    iv = int(hash_message, 16)
    a = []
    for i in range(0, 8):
        a.append(0)
        a[i] = (iv >> ((7 - i) * 32)) & 0xFFFFFFFF
    iv = a
    # 随机选取一个添加消息
    salt = secrets.token_hex(16)
    # 根据已知消息和添加消息构造攻击消息
    salt1 = byte2hex(padding(hex2byte(message))) + salt
    # 根据攻击消息确定最后一个分组的值
    salt2 = deal(padding(hex2byte(salt1)))
    index = len(salt1) // 128
    # 利用已知哈希值作为初始向量，与构造出的最后一个分组作压缩运算得到构造的
    attach = SM3.CF(iv, salt2[index])
    # 将得到的字节数组转换为十六进制字符串，保证八位转换防止删除高位0
    result = ""
    for i in attach:
        result = '%s%08x' % (result, i)
    # 返回构造出的消息和哈希值
    return salt1, result


def run_test():
    message = secrets.token_hex(16)
    hash_message = SM3.sm3(message)
    message_, hash_message_ = len_ex_attach(message, hash_message)
    Hash = SM3.sm3(message_)
    if hash_message_ == Hash:
        print("Length Extension Attach Success !")
        print("已知的消息、哈希值")
        print("Message 1:", message, "\nHash Value :", hash_message)
        print("构造的消息、哈希值")
        print("Message 2:", message_, "\nHash Value :", hash_message_)
    else:
        print("Length Extension Attach Fail !")


def time_test():
    flag = 0
    start_time = time.time()
    for i in range(1000):
        message = secrets.token_hex(16)
        hash_message = SM3.sm3(message)

        message_, hash_message_ = len_ex_attach(message, hash_message)

        Hash = SM3.sm3(message_)
        if hash_message_ == Hash:
            flag += 1
        else:
            flag = 0
    end_time = time.time()
    average = (end_time - start_time) / 1000
    if flag == 1000:
        print('全部成功')
        print("平均消耗时间 :", average)
    else:
        print("出现错误")


run_test()
time_test()
