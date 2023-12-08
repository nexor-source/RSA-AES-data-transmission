import time
from utils import *

print("\n[INFO] Initializing")
# message_A = "八十平米的小窝"*1000000  # 要加密的消息
message_A = input("请输入要发送的消息:\n")
aes_key_A = input("请输入要AES加密使用的密钥（必须是16字节，如果不是则会使用默认加密密钥）:\n")
if len(aes_key_A) == 16:
    print("密钥长度的确为16, 程序继续运行")
else:
    print("密钥长度错误，使用默认密钥abcd efgh ijkl m")
    aes_key_A = "abcd efgh ijkl m"  # AES加密解密使用的密钥，必须是16字节
# A作为消息发送方，B作为消息接收方
rsa_public_key_A, rsa_private_key_A = generate_keypair(bits = 2048)  # RSA加密使用的公钥和私钥的生成
rsa_public_key_B, rsa_private_key_B = generate_keypair(bits = 2048)  # RSA加密使用的公钥和私钥的生成

# 消息发送（A端）
print("\n[INFO] Client A side is starting to send a message")
signature_A = sign(rsa_private_key_A, message_A)  # A用自己的私钥对明文进行签名
ciphertext_A = aes_encrypt(aes_key_A, message_A)  # A用自己设定（或者随机）的AES key加密明文
ciphered_aes_key_A = encrypt(aes_key_A, rsa_public_key_B)  # A用B的RSA公钥加密自己的AES key
# print("Ciphertext:", ciphertext)

# 这里通过网络传输，B端获取到了[ciphered_aes_key_A],[ciphertext_A],[signature_A]

# 消息接收 （B端）
print("\n[INFO] Client B side is ready to receive a message")
decrypted_aes_key_B = decrypt(ciphered_aes_key_A, rsa_private_key_B)  # RSA私钥解密AES key
decrypted_message_B = aes_decrypt(decrypted_aes_key_B, ciphertext_A)  # 解密的AES key解密密文
verification_result_B = verify(rsa_public_key_A, decrypted_message_B, signature_A)  # 用A的RSA公钥对解密得到的信息进行签名验证

print()
if verification_result_B:
    print("Verify successed!")
    # 如果信息文本太长，只展示一部分
    decrypted_message_B = decrypted_message_B[:100] + "..." if len(decrypted_message_B) > 100 else decrypted_message_B
    message_A = message_A[:100] + "..." if len(message_A) > 100 else message_A
    print("Original  message:", message_A)
    print("Decrypted message:", decrypted_message_B)
else:
    print("Verify failed!")
input()





# 假如RSA的长度只有32：
#     300k字(30万字) 加密解密耗时1s, 生成密钥的时间基本不计。（图片呢？视频呢？其实本质都一样，只是字节的传输罢了，因此这里只考虑文字的传输）
#     30万字，每个字加密后4Byte，一共要传输的是1,200,000 Byte = 1.2MB，假设宽带速度是10MB/s，这里可以发现传输速度大于了加密解密速度
#     因此得出结论：RSA加密传输中 额外的计算代价 >> 额外的通信代价  （当然下载的流量也有增幅，这里没有考虑多出来的流量本身的价值，只是考虑了时间代价）
#     假设原本加密前每个字平均3Byte，使用RSA算法加密信息的速度大约在0.9MB/s
#     然而这样的速度是在max(n) = 2**32 - 1的情况下的，一般的RSA推荐长度为2048，也就是 2**2048 -1，在这样的情况下，RSA加密信息的速度会大大减少，
# 假如RSA的长度为推荐长度2048：
#     10个汉字的加密解密，密钥的生成都需要至少1s，（密钥大约1-8s）
#     每个字加密后256Byte，一共要传输2,560Byte = 2.5KB，可以发现计算时间开销远大于传输速度的增大
#     假设原本加密前每个字平均3Byte，使用RSA算法加密信息的速度大约在30B/s，简直是龟速
#     因此用RSA直接对信息进行强加密显然是不行的，如果直接对信息进行加密只能降低RSA的长度，而这会导致其更容易被破解
#     因此一种现有的加密方式是通过对称加密来对信息进行加密，而只对对称加密的密钥进行RSA加密。