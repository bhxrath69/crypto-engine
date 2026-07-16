"""crypto_engine.vault_core

Phase 1 vault crypto core: envelope encryption module.

Limitations (application-layer): OS-level swap/hibernation can still write decrypted
memory to disk unencrypted. This is known and unaddressed at this layer.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Union

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


class VaultDecryptionError(Exception):
    """Raised when decryption fails due to wrong passphrase/key or invalid data."""


class InvalidKeyError(Exception):
    """Raised when keys are malformed or cannot be parsed."""


class TamperDetectedError(Exception):
    """Raised when ciphertext/authentication fails (integrity/tamper detected)."""


# AES-256-GCM nonce is 96-bit (12 bytes) for typical security/compatibility.
_AES_GCM_NONCE_LEN = 12
_AES_KEY_LEN = 32  # 256-bit

# scrypt parameters (explicit, non-default):
# N=2**14, r=8, p=1
# Rationale: strong baseline for interactive/local use; explicit values avoid
# relying on potentially weaker library defaults.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_KEY_LEN = 32
_SCRYPT_SALT_LEN = 16


def _zero_bytearray(buf: bytearray) -> None:
    """Best-effort zeroing.

    Python cannot guarantee immediate secure memory wiping due to GC, copies,
    interpreter optimizations, and immutability of bytes/str.

    This function performs best-effort overwriting for buffers we explicitly
    control.
    """

    for i in range(len(buf)):
        buf[i] = 0


def _ensure_rsa_public_key(public_key: Union[bytes, str, RSA.RsaKey]) -> RSA.RsaKey:
    try:
        if isinstance(public_key, RSA.RsaKey):
            return public_key.publickey()
        if isinstance(public_key, (bytes, str)):
            key_bytes = public_key.encode() if isinstance(public_key, str) else public_key
            return RSA.import_key(key_bytes).publickey()
    except Exception as e:
        raise InvalidKeyError("Invalid public key") from None
    raise InvalidKeyError("Invalid public key")


def _ensure_rsa_private_encrypted_private_key_blob(
    private_key: Union[bytes, str, Any]
) -> bytes:
    # In this Phase 1, we store encrypted private key as JSON bytes.
    # Accept bytes/str (JSON) or dict (already parsed) and normalize to JSON bytes.
    if isinstance(private_key, bytes):
        return private_key
    if isinstance(private_key, str):
        return private_key.encode("utf-8")
    if isinstance(private_key, dict):
        return json.dumps(private_key, separators=(",", ":")).encode("utf-8")
    raise InvalidKeyError("Invalid private key format")


def generate_master_keypair(passphrase: str, output_dir: Union[str, Path] = None) -> None:
    """Generate RSA-2048 keypair and save an scrypt-encrypted private key.

    Writes:
      - {output_dir}/vault_public.pem
      - {output_dir}/vault_private_encrypted.pem

    The encrypted private key is stored as JSON (base64 fields) for Phase 1.
    """

    if output_dir is None:
        output_dir = Path(__file__).resolve().parent / "vault_keys"
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate RSA keypair
    key = RSA.generate(2048)
    public_key_pem: bytes = key.publickey().export_key(format="PEM")

    private_key_pem: bytes = key.export_key(format="PEM")

    # Derive KEK from passphrase using scrypt.
    salt = get_random_bytes(_SCRYPT_SALT_LEN)
    passphrase_buf = bytearray(passphrase.encode("utf-8"))
    try:
        # scrypt returns bytes; treat as sensitive material.
        kek = scrypt(
            bytes(passphrase_buf),
            salt,
            key_len=_SCRYPT_KEY_LEN,
            N=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
        )

        # Encrypt private key at rest using AES-256-GCM
        nonce = get_random_bytes(_AES_GCM_NONCE_LEN)
        cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(private_key_pem)

        # Store JSON envelope with base64 fields.
        payload = {
            "version": 1,
            "kdf": {
                "name": "scrypt",
                "N": _SCRYPT_N,
                "r": _SCRYPT_R,
                "p": _SCRYPT_P,
                "salt_b64": base64.b64encode(salt).decode("ascii"),
                "key_len": _SCRYPT_KEY_LEN,
            },
            "aead": {
                "name": "AES-256-GCM",
                "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                "tag_b64": base64.b64encode(tag).decode("ascii"),
            },
            "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
        }

        (output_dir / "vault_public.pem").write_bytes(public_key_pem)
        (output_dir / "vault_private_encrypted.pem").write_bytes(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
    finally:
        _zero_bytearray(passphrase_buf)
        # kek is bytes; we can’t reliably overwrite immutable bytes.
        # However, we can avoid storing it beyond scope.
        del private_key_pem


def encrypt_secret(public_key: Union[bytes, str, RSA.RsaKey], plaintext: bytes) -> Dict[str, Any]:
    """Encrypt plaintext with envelope encryption.

    Returns a dict:
      {ciphertext, nonce, tag, wrapped_key}
    """

    rsa_pub = _ensure_rsa_public_key(public_key)

    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")

    pt_buf = bytearray(plaintext)
    aes_key = get_random_bytes(_AES_KEY_LEN)
    nonce = get_random_bytes(_AES_GCM_NONCE_LEN)

    try:
        # Data-layer AEAD
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(bytes(pt_buf))

        # Key wrapping: RSA-OAEP (SHA-256)
        rsa_cipher = PKCS1_OAEP.new(rsa_pub, hashAlgo=SHA256)
        wrapped_key = rsa_cipher.encrypt(aes_key)

        # Return bytes (encrypted outputs)
        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag,
            "wrapped_key": wrapped_key,
        }
    finally:
        _zero_bytearray(pt_buf)
        # aes_key is bytes; cannot reliably overwrite. Avoid keeping references.
        del aes_key


def decrypt_secret(
    private_key: Union[bytes, str, Any],
    passphrase: str,
    encrypted_dict: Dict[str, Any],
) -> bytes:
    """Decrypt envelope-encrypted secret.

    On integrity failures, raises TamperDetectedError.
    On wrong passphrase, raises VaultDecryptionError.
    """

    enc_priv_json = _ensure_rsa_private_encrypted_private_key_blob(private_key)

    required_fields = {"ciphertext", "nonce", "tag", "wrapped_key"}
    if not required_fields.issubset(set(encrypted_dict.keys())):
        raise InvalidKeyError("Encrypted dict missing required fields")

    ct = encrypted_dict["ciphertext"]
    nonce = encrypted_dict["nonce"]
    tag = encrypted_dict["tag"]
    wrapped_key = encrypted_dict["wrapped_key"]

    try:
        payload = json.loads(enc_priv_json.decode("utf-8"))
    except Exception:
        raise InvalidKeyError("Invalid encrypted private key") from None

    try:
        kdf = payload["kdf"]
        salt = base64.b64decode(kdf["salt_b64"])
        # Parameters are stored for validation/compat.
        N = int(kdf["N"])
        r = int(kdf["r"])
        p = int(kdf["p"])

        aead = payload["aead"]
        priv_nonce = base64.b64decode(aead["nonce_b64"])
        priv_tag = base64.b64decode(aead["tag_b64"])
        priv_ct = base64.b64decode(payload["ciphertext_b64"])
    except Exception:
        raise InvalidKeyError("Invalid encrypted private key payload") from None

    passphrase_buf = bytearray(passphrase.encode("utf-8"))
    kek = None
    priv_pem = None
    try:
        kek = scrypt(
            bytes(passphrase_buf),
            salt,
            key_len=_SCRYPT_KEY_LEN,
            N=N,
            r=r,
            p=p,
        )

        # Decrypt private key at rest
        cipher = AES.new(kek, AES.MODE_GCM, nonce=priv_nonce)
        try:
            priv_pem = cipher.decrypt_and_verify(priv_ct, priv_tag)
        except Exception:
            # Wrong passphrase or tampered at-rest private key.
            raise VaultDecryptionError("Decryption failed") from None

        rsa_priv = RSA.import_key(priv_pem)

        # Unwrap AES key
        rsa_cipher = PKCS1_OAEP.new(rsa_priv, hashAlgo=SHA256)
        try:
            aes_key = rsa_cipher.decrypt(wrapped_key)
        except Exception:
            raise TamperDetectedError("Integrity verification failed") from None

        # Decrypt secret
        data_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = data_cipher.decrypt_and_verify(ct, tag)
        except Exception:
            raise TamperDetectedError("Integrity verification failed") from None

        return plaintext
    finally:
        if passphrase_buf is not None:
            _zero_bytearray(passphrase_buf)
        if priv_pem is not None:
            # priv_pem is bytes; cannot reliably wipe.
            del priv_pem
        if kek is not None:
            del kek

