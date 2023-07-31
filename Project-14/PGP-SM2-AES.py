from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets
from gmssl import sm2


def aes_encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_text = cipher.encrypt(pad(plain_text, AES.block_size))
    iv = cipher.iv
    return iv + encrypted_text


def aes_decrypt(encrypted_text, key):
    iv = encrypted_text[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_text[16:]), AES.block_size)
    return decrypted_text.decode()


SM2_PRIVATE_KEY = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
SM2_PUBLIC_KEY = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A69' \
                 '94B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
sm2_crypt = sm2.CryptSM2(public_key=SM2_PUBLIC_KEY, private_key=SM2_PRIVATE_KEY)


def sm2_encrypt(info):
    encode_info = sm2_crypt.encrypt(info.encode(encoding="utf-8"))
    encode_info = b64encode(encode_info).decode()
    return encode_info


def sm2_decrypt(info):
    decode_info = b64decode(info.encode())
    decode_info = sm2_crypt.decrypt(decode_info).decode(encoding="utf-8")
    return decode_info


def pgp_encrypt(message):
    message_bytes = message.encode()
    session_key = secrets.token_hex(16)
    session_key_bytes = session_key.encode()
    cipher_message = aes_encrypt(message_bytes, session_key_bytes)
    cipher_session_key = sm2_encrypt(session_key)
    a = aes_decrypt(cipher_message, session_key_bytes)
    return cipher_message, cipher_session_key


def pgp_decrypt(cipher_message, cipher_session_key):
    session_key = sm2_decrypt(cipher_session_key)
    message = aes_decrypt(cipher_message, session_key.encode())
    return message


def pgp_test():
    message = secrets.token_hex(32)
    print('Message :', message)
    cm, ck = pgp_encrypt(message)
    print("Cipher-Message :", cm)
    print("Cipher-Session-Key :", ck)
    plain = pgp_decrypt(cm, ck)
    print("Plain :", plain)
    if plain == message:
        print("PGP-SM2-AES Success")


pgp_test()
