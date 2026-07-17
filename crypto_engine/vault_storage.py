"""crypto_engine.vault_storage

Phase 2 vault storage engine.

This module stores/retrieves *already-encrypted* records produced by
`crypto_engine.vault_core`.

Crash-safety model:
- Every operation is appended as a single JSON line to {storage_dir}/vault.wal.
- A write is considered committed only after flush()+fsync().
- On startup, the WAL is replayed from the beginning.
- If the last line is partially written / corrupted, replay skips that line
  instead of failing the whole process.

No plaintext or keys are ever handled here.
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


@dataclass(frozen=True)
class VaultRecord:
    id: str
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    wrapped_key: bytes
    created_at: float
    ttl: Optional[float]
    deleted: bool

    @property
    def expires_at(self) -> Optional[float]:
        if self.ttl is None:
            return None
        return self.created_at + self.ttl

    def is_expired(self, now: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return False
        if now is None:
            now = time.time()
        return now >= self.expires_at


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


class VaultStore:
    def __init__(self, storage_dir: Union[str, Path]):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.wal_path = self.storage_dir / "vault.wal"

        # In-memory index: id -> record
        self._index: Dict[str, VaultRecord] = {}

        self._replay_wal()

    def _append_wal_line(self, obj: Dict[str, Any]) -> None:
        # obj is already JSON-serializable (bytes are b64-encoded).
        line = json.dumps(obj, separators=(",", ":"), sort_keys=True)
        data = (line + "\n").encode("utf-8")

        with open(self.wal_path, "ab", buffering=0) as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

    def _replay_wal(self) -> None:
        if not self.wal_path.exists():
            return

        with open(self.wal_path, "rb") as f:
            for raw_line in f:
                if not raw_line.strip():
                    continue

                try:
                    line = raw_line.decode("utf-8")
                    op = json.loads(line)
                except Exception:
                    # Corrupt/truncated line: skip.
                    continue

                op_type = op.get("op")
                try:
                    if op_type == "upsert":
                        rec = self._record_from_op(op)
                        self._index[rec.id] = rec
                    elif op_type == "delete":
                        rid = op["id"]
                        prev = self._index.get(rid)
                        if prev is None:
                            continue
                        self._index[rid] = VaultRecord(
                            id=prev.id,
                            ciphertext=prev.ciphertext,
                            nonce=prev.nonce,
                            tag=prev.tag,
                            wrapped_key=prev.wrapped_key,
                            created_at=prev.created_at,
                            ttl=prev.ttl,
                            deleted=True,
                        )
                except Exception:
                    # Robust replay.
                    continue

    def _record_from_op(self, op: Dict[str, Any]) -> VaultRecord:
        return VaultRecord(
            id=op["id"],
            ciphertext=_b64d(op["ciphertext"]),
            nonce=_b64d(op["nonce"]),
            tag=_b64d(op["tag"]),
            wrapped_key=_b64d(op["wrapped_key"]),
            created_at=float(op["created_at"]),
            ttl=op.get("ttl"),
            deleted=bool(op.get("deleted", False)),
        )

    def put(self, id: str, encrypted_dict: Dict[str, Any], ttl: Optional[float] = None) -> None:
        now = time.time()
        rec = {
            "op": "upsert",
            "id": id,
            "ciphertext": _b64e(encrypted_dict["ciphertext"]),
            "nonce": _b64e(encrypted_dict["nonce"]),
            "tag": _b64e(encrypted_dict["tag"]),
            "wrapped_key": _b64e(encrypted_dict["wrapped_key"]),
            "created_at": now,
            "ttl": ttl,
            "deleted": False,
        }
        self._append_wal_line(rec)
        self._index[id] = self._record_from_op(rec)

    def get(self, id: str) -> Optional[Dict[str, Any]]:
        rec = self._index.get(id)
        if rec is None or rec.deleted or rec.is_expired():
            return None

        return {
            "id": rec.id,
            "ciphertext": rec.ciphertext,
            "nonce": rec.nonce,
            "tag": rec.tag,
            "wrapped_key": rec.wrapped_key,
            "created_at": rec.created_at,
            "ttl": rec.ttl,
            "deleted": rec.deleted,
        }

    def delete(self, id: str) -> None:
        rec = self._index.get(id)
        if rec is None:
            return

        op = {"op": "delete", "id": id, "deleted": True, "ts": time.time()}
        self._append_wal_line(op)

        self._index[id] = VaultRecord(
            id=rec.id,
            ciphertext=rec.ciphertext,
            nonce=rec.nonce,
            tag=rec.tag,
            wrapped_key=rec.wrapped_key,
            created_at=rec.created_at,
            ttl=rec.ttl,
            deleted=True,
        )

    def list_ids(self) -> List[str]:
        now = time.time()
        ids: List[str] = []
        for rid, rec in self._index.items():
            if rec.deleted:
                continue
            if rec.is_expired(now=now):
                continue
            ids.append(rid)
        return sorted(ids)

    def compact(self) -> None:
        now = time.time()
        live_ops: List[Dict[str, Any]] = []
        for rec in self._index.values():
            if rec.deleted or rec.is_expired(now=now):
                continue
            live_ops.append(
                {
                    "op": "upsert",
                    "id": rec.id,
                    "ciphertext": _b64e(rec.ciphertext),
                    "nonce": _b64e(rec.nonce),
                    "tag": _b64e(rec.tag),
                    "wrapped_key": _b64e(rec.wrapped_key),
                    "created_at": rec.created_at,
                    "ttl": rec.ttl,
                    "deleted": False,
                }
            )

        tmp_path = self.storage_dir / "vault.wal.compact.tmp"
        with open(tmp_path, "wb", buffering=0) as f:
            for op in live_ops:
                f.write((json.dumps(op, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, self.wal_path)

