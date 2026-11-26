"""Encrypted file storage and link sharing.

Layers, bottom up:

* ``crypto``   - envelope encryption (AES-256-GCM, a master key wrapping per-file keys, optional
  Argon2id + HKDF password wrapping for share links). Pure functions, no I/O.
* ``names``    - filename sanitising and the ``Content-Disposition`` header.
* ``storage``  - the directory holding ciphertext blobs. Plaintext never touches the disk.
* ``attempts`` - the wrong-password budget for password-protected shares.
* ``service``  - the use cases (upload, share, download, revoke, delete, audit) on top of those.
"""
