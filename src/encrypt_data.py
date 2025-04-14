from Crypto.Cipher import AES

def pad(data):
    padding_length = 16 - len(data) % 16
    padding = bytes([padding_length] * padding_length)
    return data + padding

def encrypt(plaintext,key,iv):
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        padded_plaintext = pad(plaintext)
        ciphertext = cipher.encrypt(padded_plaintext)
        return ciphertext.hex()
    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        return None, None
    
