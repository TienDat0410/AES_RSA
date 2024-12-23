from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os
import time

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Sử dụng khóa AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Cặp khóa RSA đã được tạo và lưu thành công!")

def encrypt_file(input_file: str, output_file: str, password: str, public_key_path: str):
    salt = os.urandom(16) 
    aes_key = generate_key(password, salt)  
    iv = os.urandom(16)  


    with open(input_file, 'rb') as f:
        plaintext = f.read()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_file, 'wb') as f:
        f.write(salt + iv + encrypted_aes_key + ciphertext)

    print(f"Dữ liệu đã được mã hóa và lưu vào: {output_file}")

if __name__ == "__main__":
    input_file = "input.txt"
    encrypted_file = "encrypted_with_rsa.bin"
    password = input("Nhập mật khẩu để mã hóa: ")

    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        generate_rsa_keys()

    start_time = time.time()
    with open("time_record.txt", "w") as f:
        f.write(str(start_time))

    encrypt_file(input_file, encrypted_file, password, "public_key.pem")
