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
        length=32,  # Sử dụng khóa AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(input_file: str, output_file: str, password: str):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)  

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(salt + iv + ciphertext)

    print(f"Dữ liệu đã được mã hóa và lưu vào: {output_file}")

if __name__ == "__main__":
    input_file = "input.txt"       
    encrypted_file = "encrypted.bin" 
    decrypted_file = "decrypted.txt"  

    password = input("Nhập mật khẩu để mã hóa: ")
    start_time = time.time()
    with open("time_record.txt", "w") as f:  
        f.write(str(start_time))
    encrypt_file(input_file, encrypted_file, password)
