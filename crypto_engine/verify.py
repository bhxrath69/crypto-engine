from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

with open("public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

with open("message.txt", "rb") as f:
    message = f.read()

with open("signature.bin", "rb") as f:
    signature = f.read()

hash_obj = SHA256.new(message)

try:
    pkcs1_15.new(public_key).verify(hash_obj, signature)
    print("Signature VALID")
except:
    print("Signature INVALID")
