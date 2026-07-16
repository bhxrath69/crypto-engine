# TODO - vault phase 1

- [ ] Create `vault_core.py` with required API:
  - [ ] `generate_master_keypair(passphrase, output_dir=...)`
  - [ ] `encrypt_secret(public_key, plaintext)` using AES-256-GCM + RSA-OAEP key wrap
  - [ ] `decrypt_secret(private_key, passphrase, encrypted_dict)` with scrypt-encrypted private key at rest
  - [ ] Define custom exceptions: `VaultDecryptionError`, `InvalidKeyError`, `TamperDetectedError`
  - [ ] Best-effort memory hygiene: bytearray + zeroing (with Caveat comment)
  - [ ] No debug prints / no plaintext or key material written to disk beyond encrypted output
  - [ ] scrypt params fixed: N=2**14, r=8, p=1 with rationale comments
  - [ ] Add module docstring + limitations note

- [ ] Add `LIMITATIONS.md` documenting OS swap/hibernation limitation.

- [ ] Create pytest tests in `test_vault_core.py`:
  - [ ] Round-trip correctness
  - [ ] Tamper detection (flip ciphertext byte -> `TamperDetectedError`)
  - [ ] Wrong-passphrase handling (`VaultDecryptionError`)
  - [ ] Wrong-key handling (`TamperDetectedError`)
  - [ ] Tests isolate outputs using `tmp_path` via `generate_master_keypair(..., output_dir=tmp_path)`
  - [ ] Ensure tests do not print secrets and create no stray files

- [x] Run `pytest` and confirm all tests pass.


