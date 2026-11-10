# Encryption design (Vault)

> **Status: not implemented. No cryptographic code exists in this repository.**
> This page lists what must be decided and reviewed before any is written. CipherForge does **not**
> claim end-to-end encryption, and must not until the design below has been threat-modelled and
> reviewed.

## Intent

Vault is meant to share files so that the application server never receives plaintext: files are
encrypted on the client before upload, and only authorised recipients can decrypt them.

## Proposed flow (from the project specification)

1. The client generates a random, unique key for each file.
2. The client encrypts the file with an authenticated cipher (AES-256-GCM).
3. The ciphertext goes to encrypted object storage.
4. The per-file key is wrapped for each intended recipient and stored with the metadata needed to
   unwrap it. PostgreSQL holds metadata, authorisation relationships, wrapped-key metadata and audit
   references; the file bytes do not go in the database.
5. A recipient downloads the ciphertext and their wrapped key, then decrypts locally with key
   material they are authorised to use.

## Rules that apply from day one

- Use established, maintained cryptographic libraries (for example the browser's Web Crypto API on the
  client). **Never implement a cipher, mode, key exchange or key-derivation function by hand.**
- Never hard-code keys, and never put key material or plaintext in logs, error messages or the audit
  trail. The log redaction layer is a safety net, not a design.
- TLS stays mandatory. TLS protects transport, server-side storage encryption protects stored
  infrastructure, and neither one is end-to-end encryption.

## Open questions that must be answered first

| Topic | Question |
| --- | --- |
| Nonce / IV handling | How are nonces generated, and how is uniqueness guaranteed for each key? |
| Recipient keys | How is a recipient's public key authenticated, and how is it bound to their identity? |
| Key wrapping | Which wrapping scheme, from which vetted library, with which parameters? |
| Key lifecycle | Rotation, revocation, multi-device access, and the lost-key and recovery policy. |
| Deletion | What can truthfully be promised about secure deletion? |
| Compromised client | What does the system still protect if the browser or device is compromised? |
| Metadata | What do the server and storage learn (file sizes, names, recipients, timing)? |
| Audit | What is logged for every upload, download, share and denial, without leaking secrets? |

## Before implementation

1. Write a STRIDE threat model for Vault and add it to [threat-model.md](threat-model.md).
2. Choose the primitives, libraries and parameters, and record the reasons here.
3. Get an independent review of the design.
4. Only then implement, with known-answer tests, tamper tests and round-trip tests.

Until all of that is done, any description of Vault must say it is a design in progress.
