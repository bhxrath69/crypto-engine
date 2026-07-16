from Crypto.PublicKey import RSA

# Generate RSA key pair
key = RSA.generate(2048)

# Private key
private_key = key.export_key()

# Public key
public_key = key.publickey().export_key()

# Save private key
with open("private.pem", "wb") as f:
    f.write(private_key)

# Save public key
with open("public.pem", "wb") as f:
    f.write(public_key)

print("Keys generated successfully!")
