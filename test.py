import random
from gmssl import sm3,func,sm2,sm4
import binascii


#SM2 密钥对
# 在线测试：https://www.zytool.cn/util/SMUtil 注意公钥的04

PrivateKey = '749EA05A3C8D2E34176E50BEF37CAB60BBF991A88E99DA2758D9470DBB759214'
PublicKey = '0B4E1EF13B3C89605EFFFC76051C34AE877D85CE8722F619B8E344BA6E95E4525E77A86B8FD7441799342ADF88658D93DDB843EE5A3A90A8492A64D58415A50D'

# 随机字符串生成
generate_random = lambda n: "".join(random.choice("1456u7YUIOP89qazdcrfvtgbyhnjmiklopQJWE0R23TLKHGFDSAZXCVBNM") for _ in range(n))

randstr = "ut8KtJVr6xI8juJWHp"

print(randstr)

#sm3 哈希计算
data_byte = randstr.encode('utf-8')
hash_randstr = sm3.sm3_hash(func.bytes_to_list(data_byte))

print(hash_randstr,len(hash_randstr))



iv = hash_randstr[:32]
key = hash_randstr[32:]

print("iv:",iv)
print("key:",key)

# sm2 加密

sm2_crypt = sm2.CryptSM2(private_key="",public_key=PublicKey,mode=1)

data = randstr.encode()
enc_data = sm2_crypt.encrypt(data).hex()
print(enc_data,type(enc_data))



# def decrypt(key1,enctext):
#     sm2_crypt = sm2.CryptSM2(private_key=key1,public_key=PublicKey)
#     cipher = bytes.fromhex(enctext)
#     dec_data = sm2_crypt.decrypt(cipher).decode()
#     print(dec_data)


# decrypt(PrivateKey,enc_data)


# SM2 解密
# text = "137C452C9474250A1865BA45CFDB5D7EFE1E6EC7D79CD7A4E07644E907EBE736DE0B03822F56D9CB63B2913D9232D8BE5F315923BA9A07BBDE7280152817FBAFBD092058ED02FF3316EC6C5E69792DCD3E1F681D5E3EB9A74D5A9EAA343DA4C5AFEDE532F4525C3175CE1DF3"
# sm2_decrypt = sm2.CryptSM2(private_key=PrivateKey,public_key="",mode=1)
# cipher = bytes.fromhex(text)
# dec_data = sm2_decrypt.decrypt(cipher).decode()
# print(dec_data) 


#SM4 加密

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

p_text = '1234'


sm4_crypt = SM4_cbc()
cipher = sm4_crypt.encrypt_cbc(key,iv,p_text)
cipher_hex = cipher.decode()

print(cipher_hex)

