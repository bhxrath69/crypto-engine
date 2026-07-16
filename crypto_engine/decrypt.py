from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Load private key
with open("private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

cipher = PKCS1_OAEP.new(private_key)

# Load encrypted message
with open("encrypted.bin", "rb") as f:
    ciphertext = f.read()

message = cipher.decrypt(ciphertext)

print("Decrypted message:", message.decode())
