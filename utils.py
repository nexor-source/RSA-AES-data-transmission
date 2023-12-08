import random
from sympy import isprime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import os
import time
import hashlib

def is_prime(n):
    """检查一个数是否为质数"""
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_keypair(bits = 2048):
    """生成RSA密钥对"""
    start_time = time.time()
    
    # 选择两个不同的质数
    p = random_prime(bits = bits // 2)
    q = random_prime(bits = bits // 2)

    # 计算n和φ(n)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # 选择公钥e，确保1 < e < φ(n) 且 e与φ(n)互质
    e = random_coprime(phi_n)

    # 计算私钥d，满足d * e ≡ 1 (mod φ(n))
    d = mod_inverse(e, phi_n)

    # 返回公钥和私钥
    public_key = (n, e)
    private_key = (n, d)

    end_time = time.time()
    key_generation_time = end_time - start_time
    print(f"RSA Key_pair generation time: {key_generation_time:.2f} seconds")
    return public_key, private_key

# def random_prime():
#     """生成一个随机质数"""
#     while True:
#         num = random.randint(2**15, 2**16)
#         if is_prime(num):
#             return num

def random_prime(bits = 2048):
    """生成一个指定位数的随机质数"""
    while True:
        num = random.getrandbits(bits)
        if isprime(num):
            return num

def random_coprime(phi_n):
    """生成与φ(n)互质的随机数"""
    while True:
        e = random.randint(2, phi_n - 1)
        if gcd(e, phi_n) == 1:
            return e

def gcd(a, b):
    """计算最大公约数"""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    """计算模反元素"""
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def encrypt(message, public_key):
    """使用公钥加密消息"""
    start_time = time.time()
    
    n, e = public_key
    ciphertext = [pow(ord(char), e, n) for char in message]

    end_time = time.time()
    encryption_time = end_time - start_time
    print(f"RSA Encryption time: {encryption_time:.2f} seconds")
    return ciphertext

def decrypt(ciphertext, private_key):
    """使用私钥解密消息"""
    start_time = time.time()
    
    n, d = private_key
    decrypted_message = ''.join([chr(pow(char, d, n)) for char in ciphertext])

    end_time = time.time()
    decryption_time = end_time - start_time
    print(f"RSA Decryption time: {decryption_time:.2f} seconds")
    return decrypted_message

def aes_encrypt(key, plaintext):
    # 生成随机的IV（Initialization Vector）
    start_time = time.time()
    iv = os.urandom(16)

    # 使用PKCS7填充
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    # 创建AES加密器
    key = key.encode('utf-8')
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 加密数据
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    end_time = time.time()
    encryption_time = end_time - start_time
    print(f"AES Encryption time: {encryption_time:.2f} seconds")
    # 返回IV和密文
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    # 从密文中提取IV
    start_time = time.time()
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    # 创建AES解密器
    key = key.encode('utf-8')
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # 解密数据
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # 使用PKCS7反向填充
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    end_time = time.time()
    encryption_time = end_time - start_time
    print(f"AES Decryption time: {encryption_time:.2f} seconds")
    return plaintext.decode('utf-8')

# 自定义大数库，用于模幂运算
def modexp(base, exponent, modulus):
    result = 1
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent //= 2
        base = (base * base) % modulus
    return result

# 自定义RSA签名和验证
def sign(private_key, message):
    start_time = time.time()
    # 将消息进行哈希
    hashed_message = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')
    # 对哈希值进行模幂运算，得到签名
    signature = modexp(hashed_message, private_key[1], private_key[0])
    end_time = time.time()
    sign_time = end_time - start_time
    print(f"RSA sign time: {sign_time:.2f} seconds")
    return signature

def verify(public_key, message, signature):
    start_time = time.time()
    # 将消息进行哈希
    hashed_message = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')
    # 对签名进行模幂运算，得到哈希值
    hash_from_signature = modexp(signature, public_key[1], public_key[0])
    # 验证哈希值是否一致
    end_time = time.time()
    verify_time = end_time - start_time
    print(f"RSA verify time: {verify_time:.2f} seconds")
    return hash_from_signature == hashed_message
