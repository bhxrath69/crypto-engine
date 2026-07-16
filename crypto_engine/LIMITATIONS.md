# Limitations

Even with application-layer encryption, OS-level behavior can still expose decrypted plaintext.

## Swap / Hibernation / Crash dumps
- If the operating system swaps memory to disk, hibernates, or writes memory snapshots (e.g., crash dumps), decrypted sensitive data *may* be written to disk in unencrypted form.
- This is a known, unaddressed limitation at the application layer for this project.

