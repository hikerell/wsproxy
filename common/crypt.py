from Crypto.Cipher import AES
import base64
import binascii
import hashlib

def md5hash(s: bytes) -> bytes:
    return hashlib.md5(s).hexdigest().encode()

def sha256hash(s: bytes) -> bytes:
    return hashlib.sha256(s).hexdigest().encode()

class AesCbcCipher(object):
    """
    AES CBC加密, key和iv使用同一个, 填充pkcs7
    数据块128字节，key为16字节，iv为16字节
    """
    def __init__(self, key: bytes):
        self._key = self._iv = key
        self.enc_cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        self.dec_cipher = AES.new(self._key, AES.MODE_CBC, self._iv)

    def pkcs7padding(self, data: bytes) -> bytes:
        """
        明文使用PKCS7填充
        最终调用AES加密方法时，传入的是一个byte数组，要求是16的整数倍，因此需要对明文进行处理
        :param data: 待加密内容(明文)
        :return:
        """
        bs = AES.block_size  # 16
        # tips：utf-8编码时，英文占1个byte，而中文占3个byte
        padding_size = bs - len(data) % bs
        # tips：chr(padding)看与其它语言的约定，有的会使用'\0'
        padding_data = bytes(chr(padding_size) * padding_size, encoding='utf-8')
        return data + padding_data

    def pkcs7unpadding(self, data: bytes) -> bytes:
        """
        处理使用PKCS7填充过的数据
        :param data: 解密后的字符串
        :return:
        """
        unpadding = data[-1]
        return data[0:len(data)-unpadding]

    def encrypt(self, data: bytes) -> bytes:
        encrypt_bytes = self.enc_cipher.encrypt(self.pkcs7padding(data))
        return base64.b64encode(encrypt_bytes)

    def decrypt(self, data: bytes) -> bytes:
        decrypt_bytes = self.dec_cipher.decrypt(base64.b64decode(data))
        return self.pkcs7unpadding(decrypt_bytes)


class AesEcbCipher(object):
    """
    AES CBC加密, key和iv使用同一个, 填充pkcs7
    数据块128字节，key为16字节，iv为16字节
    """
    def __init__(self, key: bytes):
        if not isinstance(key, bytes):
            key = bytes(str(key), 'utf-8')
        self._key = md5hash(key)[:16]
        self.cipher = AES.new(self._key, AES.MODE_ECB)

    def pkcs7padding(self, data: bytes) -> bytes:
        """
        明文使用PKCS7填充
        最终调用AES加密方法时，传入的是一个byte数组，要求是16的整数倍，因此需要对明文进行处理
        :param data: 待加密内容(明文)
        :return:
        """
        bs = AES.block_size  # 16
        # tips：utf-8编码时，英文占1个byte，而中文占3个byte
        padding_size = bs - len(data) % bs
        # tips：chr(padding)看与其它语言的约定，有的会使用'\0'
        padding_data = bytes(chr(padding_size) * padding_size, encoding='utf-8')
        return data + padding_data

    def pkcs7unpadding(self, data: bytes) -> bytes:
        """
        处理使用PKCS7填充过的数据
        :param data: 解密后的字符串
        :return:
        """
        unpadding = data[-1]
        return data[0:len(data)-unpadding]

    def encrypt(self, data: bytes) -> bytes:
        encrypt_bytes = self.cipher.encrypt(self.pkcs7padding(data))
        return base64.b64encode(encrypt_bytes)

    def decrypt(self, data: bytes) -> bytes:
        decrypt_bytes = self.cipher.decrypt(base64.b64decode(data))
        return self.pkcs7unpadding(decrypt_bytes)

if __name__ == "__main__":
    aes_key = b'1'*16
    print(b'aes_key:' + aes_key)

    cipher = AesEcbCipher(aes_key)
    # 对英文加密
    source_en = b'Hello!'*1000
    encrypt_en = cipher.encrypt(source_en)
    #print(encrypt_en)
    source_en = b'BBBB!'*1000
    encrypt_en = cipher.encrypt(source_en)
    print(encrypt_en)
    # 解密
    decrypt_en = cipher.decrypt(encrypt_en)
    print(decrypt_en)
    print(source_en == decrypt_en)



