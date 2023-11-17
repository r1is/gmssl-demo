import random
from gmssl import sm3,func,sm2,sm4
import binascii
import base64

generate_random = lambda n: "".join(random.choice("1456u7YUIOP89qazdcrfvtgbyhnjmiklopQJWE0R23TLKHGFDSAZXCVBNM") for _ in range(n))

# 在线测试：https://www.zytool.cn/util/SMUtil 注意公钥的04
PrivateKey = '749EA05A3C8D2E34176E50BEF37CAB60BBF991A88E99DA2758D9470DBB759214'
PublicKey = '0B4E1EF13B3C89605EFFFC76051C34AE877D85CE8722F619B8E344BA6E95E4525E77A86B8FD7441799342ADF88658D93DDB843EE5A3A90A8492A64D58415A50D'

def hex_to_base64(hex_str):
    bytes_from_hex = binascii.unhexlify(hex_str)
    base64_str = base64.b64encode(bytes_from_hex)
    return base64_str.decode('utf-8')

#SM4 加解密准备工作
class SM4_cbc:
    def __init__(self):
        self.crypt_sm4 = sm4.CryptSM4()

    def str_to_strBin(self,hex_str):
        hex_data = hex_str.encode('utf-8')
        str_bin = binascii.unhexlify(hex_data)
        return str_bin.decode('utf-8')
    
    def encrypt_cbc(self,cbc_key,iv,value):
        crypt_cbc = self.crypt_sm4
        crypt_cbc.set_key(binascii.a2b_hex(cbc_key),sm4.SM4_ENCRYPT)
        Enc_value = crypt_cbc.crypt_cbc(binascii.a2b_hex(iv),value.encode())
        return binascii.b2a_hex(Enc_value)

    def decrypt_cbc(self,cbc_key,iv,value):
        crypt_cbc = self.crypt_sm4
        crypt_cbc.set_key(binascii.a2b_hex(cbc_key),sm4.SM4_DECRYPT)
        return crypt_cbc.crypt_cbc(binascii.a2b_hex(iv),value)

# 随机生成字符串函数
generate_random_string = lambda n: "".join(random.choice("1456u7YUIOP89qazdcrfvtgbyhnjmiklopQJWE0R23TLKHGFDSAZXCVBNM") for _ in range(n))

# sm3 hash
def sm3_hash(data: str) -> str:
    data_byte = data.encode('utf-8')
    hash_data = sm3.sm3_hash(func.bytes_to_list(data_byte))
    return hash_data


# 生成用于sm4加密的iv,key
def generate_sm4_key_iv(hash_randstr: str) -> tuple:
    iv = hash_randstr[:32]
    key = hash_randstr[32:]
    return iv, key

#sm4 对称加密
def sm4_encrypt(iv: str, key: str, plaintext: str) -> str:
    sm4_crypt = SM4_cbc()
    enc_data = sm4_crypt.encrypt_cbc(key,iv,plaintext)
    return enc_data.decode()

#sm4 对称解密
def sm4_decrypt(iv: str, key: str, ciphertext: str) -> str:
    val = hex_to_base64(ciphertext)
    sm4_crypt = SM4_cbc()
    dec_data = sm4_crypt.decrypt_cbc(key,iv,base64.b64decode(val))
    return dec_data.decode()

# sm2非对称加密 
def sm2_encrypt(text: str, PublicKey: str) -> str:
    sm2_crypt = sm2.CryptSM2(private_key="",public_key=PublicKey,mode=1)
    data = text.encode()
    enc_data = sm2_crypt.encrypt(data).hex()
    return enc_data

# sm2 非对称解密
def sm2_decrypt(enctext: str,key1: str) -> str:
    sm2_decrypt = sm2.CryptSM2(private_key=key1,public_key="",mode=1)
    cipher = bytes.fromhex(enctext)
    dec_data = sm2_decrypt.decrypt(cipher).decode()
    return dec_data
   

# SM2 签名
def sm2_sign(private_key, message):
    sm2_crypt = sm2.CryptSM2(
        public_key="", private_key=private_key)  
    # 签名
    random_hex_str = func.random_hex(sm2_crypt.para_len)
    sign = sm2_crypt.sign(message, random_hex_str)
    return sign

# SM2 验签
def sm2_verify(public_key, sign, message):
    sm2_crypt = sm2.CryptSM2(
        public_key=public_key, private_key="")  
    # 验签
    verify = sm2_crypt.verify(sign, message)
    return verify


if __name__ =="__main__":
    
    randstr = generate_random(18)
    # randstr = "ut8KtJVr6xI8juJWHp"
    hash_randstr = sm3_hash(randstr)

    # print(randstr,hash_randstr,len(hash_randstr))
    iv,key = generate_sm4_key_iv(hash_randstr)
    print("iv:",iv,"key:",key)

    # 测试sm2 加密随机数
    print("随机数:",randstr)
    enctext = sm2_encrypt(randstr,PublicKey)
    print("sm2加密:",enctext)

    text = sm2_decrypt(enctext,PrivateKey)
    print("sm2解密:",text)

    # 测试sm4 加密
    enc_data = sm4_encrypt(iv,key,randstr)
    print("sm4加密:",enc_data)

    print("sm4解密:",sm4_decrypt(iv,key,enc_data))