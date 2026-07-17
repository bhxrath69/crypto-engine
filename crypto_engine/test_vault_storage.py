import os
import time
from pathlib import Path

import pytest

from crypto_engine.vault_core import encrypt_secret, generate_master_keypair
from crypto_engine.vault_storage import VaultStore


def _load_bytes(path: Path) -> bytes:
    return path.read_bytes()


def _gen_keys(tmp_path: Path, passphrase: str):
    generate_master_keypair(passphrase, output_dir=tmp_path)
    public_key = _load_bytes(tmp_path / "vault_public.pem")
    return public_key


def _encrypt_dummy(public_key: bytes, plaintext: bytes = b"x"):
    # vault_core encrypts bytes; we store only the resulting encrypted_dict.
    return encrypt_secret(public_key, plaintext)


def test_put_then_get_returns_correct_record(tmp_path: Path):
    public_key = _gen_keys(tmp_path, "pw")
    store = VaultStore(tmp_path)

    enc = _encrypt_dummy(public_key, b"hello")
    store.put("id1", enc, ttl=None)

    rec = store.get("id1")
    assert rec is not None
    assert rec["id"] == "id1"
    assert rec["ciphertext"] == enc["ciphertext"]
    assert rec["nonce"] == enc["nonce"]
    assert rec["tag"] == enc["tag"]
    assert rec["wrapped_key"] == enc["wrapped_key"]
    assert rec["deleted"] is False


def test_delete_then_get_returns_none(tmp_path: Path):
    public_key = _gen_keys(tmp_path, "pw")
    store = VaultStore(tmp_path)

    enc = _encrypt_dummy(public_key, b"hello")
    store.put("id1", enc)
    store.delete("id1")

    assert store.get("id1") is None
    assert store.list_ids() == []


def test_ttl_expiry_returns_none(tmp_path: Path, monkeypatch):
    public_key = _gen_keys(tmp_path, "pw")
    store = VaultStore(tmp_path)

    enc = _encrypt_dummy(public_key, b"hello")
    store.put("id1", enc, ttl=0.05)

    # Fast-forward time by monkeypatching time.time.
    start = time.time()

    def fake_time():
        return start + 10

    monkeypatch.setattr(time, "time", fake_time)

    assert store.get("id1") is None
    assert "id1" not in store.list_ids()


def test_wal_replay_recovers_state(tmp_path: Path):
    public_key = _gen_keys(tmp_path, "pw")

    store1 = VaultStore(tmp_path)
    enc1 = _encrypt_dummy(public_key, b"a")
    enc2 = _encrypt_dummy(public_key, b"b")

    store1.put("id1", enc1, ttl=None)
    store1.put("id2", enc2, ttl=None)
    store1.delete("id1")

    # New instance should replay WAL.
    store2 = VaultStore(tmp_path)
    assert store2.get("id1") is None

    rec2 = store2.get("id2")
    assert rec2 is not None
    assert rec2["id"] == "id2"


def test_crash_simulation_truncated_last_line_skipped(tmp_path: Path):
    public_key = _gen_keys(tmp_path, "pw")

    store1 = VaultStore(tmp_path)
    enc1 = _encrypt_dummy(public_key, b"a")
    enc2 = _encrypt_dummy(public_key, b"b")

    store1.put("id1", enc1)
    store1.put("id2", enc2)

    wal_path = tmp_path / "vault.wal"
    original = wal_path.read_bytes()

    # Corrupt/truncate last line.
    # Find last newline; keep everything up to it, then add partial JSON.
    last_nl = original.rfind(b"\n")
    assert last_nl != -1

    corrupted = original[:last_nl + 1] + b"{\"op\":\"upsert\",\"id\":\"BROKEN\""
    wal_path.write_bytes(corrupted)

    # Ensure new instance boots and recovers PRIOR valid records.
    store2 = VaultStore(tmp_path)
    assert store2.get("id1") is not None
    assert store2.get("id2") is not None
    assert store2.get("BROKEN") is None


def test_compact_reduces_wal_and_preserves_live_state(tmp_path: Path):
    public_key = _gen_keys(tmp_path, "pw")

    store = VaultStore(tmp_path)

    enc1 = _encrypt_dummy(public_key, b"a")
    enc2 = _encrypt_dummy(public_key, b"b")

    store.put("id1", enc1)
    store.put("id2", enc2)
    store.delete("id1")

    wal_before = (tmp_path / "vault.wal").stat().st_size

    store.compact()

    wal_after = (tmp_path / "vault.wal").stat().st_size
    assert wal_after < wal_before

    # State after compaction should match.
    assert store.get("id1") is None
    rec2 = store.get("id2")
    assert rec2 is not None
    assert store.list_ids() == ["id2"]

    # Also ensure reload after compaction is consistent.
    store2 = VaultStore(tmp_path)
    assert store2.get("id1") is None
    assert store2.get("id2") is not None

