from Crypto.Cipher import AES
import os

def unpad(data):
    padding_length = data[-1]
    if padding_length < 1 or padding_length > 16:
        raise ValueError("Invalid padding encountered")
    return data[:-padding_length]

def decrypt(key, iv, encrypted_data):
    try:
        decoded_key = bytes.fromhex(key)
        iv_bytes = bytes.fromhex(iv)
        encrypted_data = bytes.fromhex(encrypted_data)
        if len(decoded_key) != 32:
            raise ValueError("Incorrect AES key length")
        cipher = AES.new(decoded_key, AES.MODE_CBC, iv_bytes)
        decrypted_data = unpad(cipher.decrypt(encrypted_data))
        return decrypted_data
    except Exception as e:
        print(f"An error occurred during decryption: {e}")
