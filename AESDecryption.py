from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import time
import os


def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f:
        data = f.read()

    salt = data[:16]  
    iv = data[16:32]  
    ciphertext = data[32:]  


    key = generate_key(password, salt)


    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"Dữ liệu đã được giải mã và lưu vào: {output_file}")

if __name__ == "__main__":     
    encrypted_file = "encrypted.bin" 
    decrypted_file = "decrypted.txt"  

    password = input("Nhập mật khẩu để giải mã: ")

    with open("time_record.txt", "r") as f:
        start_time = float(f.read())
        
        
    decrypt_file(encrypted_file, decrypted_file, password)
    #đo time
    end_time = time.time()
    elapsed_time = end_time - start_time
    minutes = int(elapsed_time // 60)
    seconds = int(elapsed_time % 60)
    print(f"Thời gian thực hiện: {minutes} phút {seconds} giây")