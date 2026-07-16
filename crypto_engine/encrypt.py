from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Load public key
with open("public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

cipher = PKCS1_OAEP.new(public_key)

message = input("Enter message: ").encode()

ciphertext = cipher.encrypt(message)

# Save encrypted data
with open("encrypted.bin", "wb") as f:
    f.write(ciphertext)

print("Message encrypted!")
