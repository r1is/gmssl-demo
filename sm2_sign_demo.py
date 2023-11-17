from gmssl import sm2, func

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

if __name__ == '__main__':
    PrivateKey = '749EA05A3C8D2E34176E50BEF37CAB60BBF991A88E99DA2758D9470DBB759214'
    PublicKey = '0B4E1EF13B3C89605EFFFC76051C34AE877D85CE8722F619B8E344BA6E95E4525E77A86B8FD7441799342ADF88658D93DDB843EE5A3A90A8492A64D58415A50D'
    message = "{'name':'张三','age':'18'}"
    message = message.encode('utf-8')
    sign = sm2_sign(PrivateKey, message)
    print(sign)
    verify = sm2_verify(PublicKey, sign, message)
    print(verify)
