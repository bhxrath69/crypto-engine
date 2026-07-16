from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

with open("private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

message = input("Message to sign: ").encode()

hash_obj = SHA256.new(message)

signature = pkcs1_15.new(private_key).sign(hash_obj)

with open("signature.bin", "wb") as f:
    f.write(signature)

with open("message.txt", "wb") as f:
    f.write(message)

print("Message signed")
