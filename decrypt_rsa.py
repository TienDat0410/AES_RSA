from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import time
import os


def decrypt_aes_key(encrypted_aes_key: bytes, private_key_path: str) -> bytes:
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    return private_key.decrypt(
        encrypted_aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_file(input_file: str, output_file: str, private_key_path: str):
    with open(input_file, 'rb') as f:
        data = f.read()

    salt = data[:16] 
    iv = data[16:32]  
    encrypted_aes_key = data[32:32+256]  # 256 byte 
    ciphertext = data[32+256:] 

    aes_key = decrypt_aes_key(encrypted_aes_key, private_key_path)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"Dữ liệu đã được giải mã và lưu vào: {output_file}")

if __name__ == "__main__":
    encrypted_file = "encrypted_with_rsa.bin"  
    decrypted_file = "decrypted.txt"  
    private_key_file = "private_key.pem" 

    with open("time_record.txt", "r") as f:
        start_time = float(f.read())

    start_decrypt_time = time.time()
    decrypt_file(encrypted_file, decrypted_file, private_key_file)

    end_time = time.time()
    elapsed_time = end_time - start_time
    minutes = int(elapsed_time // 60)
    seconds = int(elapsed_time % 60)
    print(f"Thời gian thực hiện (mã hóa + giải mã): {minutes} phút {seconds} giây")
