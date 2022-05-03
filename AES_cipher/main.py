
from Crypto.Cipher import AES
from secrets import token_bytes

key = token_bytes(16)

def encrypt(text):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('ascii'))
    return nonce, ciphertext, tag

def decrypt(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plain_text = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plain_text.decode('ascii')
    except:
        return False

nonce, ciphertext, tag = encrypt(input('Type Text: '))
plain_text = decrypt(nonce, ciphertext, tag)
print(f'The cipher text: {ciphertext}')
if not plain_text:
    print(f'Incorrect text')
else:
    print(f'This is the text: {plain_text}')