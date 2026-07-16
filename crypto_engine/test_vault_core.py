import base64
import json
from pathlib import Path

import pytest

from crypto_engine.vault_core import (
    TamperDetectedError,
    VaultDecryptionError,
    InvalidKeyError,
    decrypt_secret,
    encrypt_secret,
    generate_master_keypair,
)


def _load_bytes(path: Path) -> bytes:
    return path.read_bytes()


def test_round_trip_correctness(tmp_path: Path):
    passphrase = "correct horse battery staple"
    plaintext = b"vault secret payload"

    generate_master_keypair(passphrase, output_dir=tmp_path)

    public_key = _load_bytes(tmp_path / "vault_public.pem")
    private_key_enc = _load_bytes(tmp_path / "vault_private_encrypted.pem")

    encrypted = encrypt_secret(public_key, plaintext)
    decrypted = decrypt_secret(private_key_enc, passphrase, encrypted)

    assert decrypted == plaintext


def test_tamper_detection_flip_ciphertext_byte(tmp_path: Path):
    passphrase = "pass"
    plaintext = b"attack at dawn"

    generate_master_keypair(passphrase, output_dir=tmp_path)

    public_key = _load_bytes(tmp_path / "vault_public.pem")
    private_key_enc = _load_bytes(tmp_path / "vault_private_encrypted.pem")

    encrypted = encrypt_secret(public_key, plaintext)

    ct = bytearray(encrypted["ciphertext"])
    ct[0] ^= 0x01  # flip first byte
    encrypted["ciphertext"] = bytes(ct)

    with pytest.raises(TamperDetectedError):
        decrypt_secret(private_key_enc, passphrase, encrypted)


def test_wrong_passphrase_handling(tmp_path: Path):
    passphrase = "right"
    wrong_passphrase = "wrong"
    plaintext = b"sensitive"

    generate_master_keypair(passphrase, output_dir=tmp_path)

    public_key = _load_bytes(tmp_path / "vault_public.pem")
    private_key_enc = _load_bytes(tmp_path / "vault_private_encrypted.pem")

    encrypted = encrypt_secret(public_key, plaintext)

    with pytest.raises(VaultDecryptionError):
        decrypt_secret(private_key_enc, wrong_passphrase, encrypted)


def test_wrong_key_handling_raises_tamper_or_decryption(tmp_path: Path):
    passphrase_1 = "p1"
    passphrase_2 = "p2"
    plaintext = b"data that must not decrypt under wrong key"

    # Keypair 1
    generate_master_keypair(passphrase_1, output_dir=tmp_path / "k1")
    # Keypair 2
    generate_master_keypair(passphrase_2, output_dir=tmp_path / "k2")

    public_key_1 = _load_bytes(tmp_path / "k1" / "vault_public.pem")
    private_key_enc_wrong = _load_bytes(tmp_path / "k2" / "vault_private_encrypted.pem")

    encrypted = encrypt_secret(public_key_1, plaintext)

    # With wrong private key, AES-GCM should fail integrity.
    with pytest.raises(TamperDetectedError):
        decrypt_secret(private_key_enc_wrong, passphrase_2, encrypted)


def test_invalid_encrypted_dict_missing_fields(tmp_path: Path):
    passphrase = "p"
    generate_master_keypair(passphrase, output_dir=tmp_path)

    private_key_enc = _load_bytes(tmp_path / "vault_private_encrypted.pem")

    with pytest.raises(InvalidKeyError):
        decrypt_secret(private_key_enc, passphrase, {"ciphertext": b""})

