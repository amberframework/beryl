# Beryl

Security for Amber V2, from the Amberverse crew.

Beryl owns the security side of an Amber app:

- **Policies:** authentication and authorization, written as named, statement-shaped policies and enforced at each step of a request.
- **Supply chain:** dependencies, CI actions, images and toolchains pinned and verified by hash.
- **Secrets:** kept out of source and delivered to the app by Mo, the secrets broker.
- **Disclosure:** a private path to report flaws, and advisories once fixes ship.

Status: design in progress. The integration plan lives with the Amber maintainers.

## Cryptography

`Beryl::Crypto` implements cryptographic standards in Crystal, with no C library underneath. It is opt-in today. It becomes a default once its own gates pass, and every pull request must pass them to merge: the published test vectors (NIST CAVP and the RFCs), Wycheproof, three constant-time checks (timing statistics after dudect, a Valgrind memory-checker run with every secret marked undefined, and a check of the compiled LLVM IR), and a differential against OpenSSL on random inputs.

Available now (milestones B1 and B2, and F1 and F2 for speed): SHA-224, SHA-256, SHA-384, SHA-512 and SHA-512/256; HMAC; HKDF; authenticated encryption with XChaCha20-Poly1305, ChaCha20-Poly1305 and AES-GCM; and, for formats that already exist, MD5, SHA-1, PBKDF2 and AES-CBC. The hashes and ciphers run on the processor's own SHA, AES, carry-less multiply and vector instructions on Apple Silicon, Linux AArch64 and x86-64, and on portable code everywhere else. Measured against OpenSSL 4.1.0 on an Apple M1 Max, all 42 hash and HMAC measurements (64 B, 1 KiB and 1 MiB) and all 32 authenticated-encryption measurements (sealing and opening at 64 B, 1 KiB, 16 KiB and 1 MiB) are at least as fast, with the whole 95% interval on that side; the tables are in the documents below.

Public-key cryptography (milestone B3): X25519, Ed25519, ECDSA and ECDH on P-256, ECDSA verification on P-384, and RSA (PKCS #1 v1.5 and PSS signatures, OAEP) at 2,048 to 4,096 bits. Since milestone F3, on an Apple M4, P-256 key generation and ECDSA verification, P-384 verification, Ed25519 and RSA-2048 signing are as fast as OpenSSL or faster; P-256 signing and ECDH (about 1.1 times slower), RSA verification and RSA-3072 and RSA-4096 (1.5 to 1.6 times slower) are not yet, and [docs/crypto/public-key.md](docs/crypto/public-key.md) states each measured ratio.

```crystal
require "beryl"

Beryl::Crypto.digest("contents of a file")                             # SHA-256
tag = Beryl::Crypto.authenticate("message", key: secret_key)           # HMAC-SHA256
Beryl::Crypto.verify_authentication("message", tag, key: secret_key)   # => true
Beryl::Crypto.derive_key(shared_secret, info: "cookies", bytesize: 32) # HKDF-SHA256
sealed = Beryl::Crypto.encrypt("message", key: key_of_32_bytes)         # XChaCha20-Poly1305
Beryl::Crypto.decrypt(sealed, key: key_of_32_bytes)                    # => Bytes, or nil if changed
signing_key = Beryl::Crypto.generate_signing_key                         # Ed25519
signature = Beryl::Crypto.sign("message", signing_key: signing_key)
Beryl::Crypto.verify_signature("message", signature, verification_key: signing_key.verification_key) # => true
```

The calls on `Beryl::Crypto` always use the algorithm Beryl recommends today. `Beryl::Crypto::V1` names each algorithm exactly, and `Beryl::Crypto::Compatibility` holds the old ones. See [docs/crypto/hashes-and-macs.md](docs/crypto/hashes-and-macs.md) [docs/crypto/ciphers-and-aeads.md](docs/crypto/ciphers-and-aeads.md) and [docs/crypto/public-key.md](docs/crypto/public-key.md) for the full list, the test vectors, how to run each check and the measured speed against OpenSSL.

## Certificates

`Beryl::Certificates` (milestone B4) reads X.509 certificates, CRLs and private key files and verifies certificate chains for TLS against the pinned Mozilla root set or the system bundle, with host names checked as RFC 9525 says. Every applicable case of x509-limbo passes, and its verdicts match OpenSSL 4.1.0 on 40,960 Certificate Transparency log entries. Reading a certificate is 6.3 times as fast as OpenSSL (4.1 times slower when its public key is built too, mostly RSA key setup); verifying a chain is 1.5 to 2 times slower, held back by the P-256 and RSA speed above. See [docs/certificates.md](docs/certificates.md).

```crystal
chain = Beryl::Certificates.read_pem_chain(File.read("chain.pem"))
Beryl::Certificates.verify_server_chain(chain, hostname: "example.com") # => the verified path, or raises
```

## Development

```sh
minecart install --frozen
crystal-alpha spec                                 # unit specs and every published vector
crystal-alpha spec -Dberyl_portable_hashes         # the same, on the portable hashes alone
crystal-alpha spec -Dberyl_portable_ciphers        # the same, on the portable ciphers alone
crystal-alpha spec --release --tag differential    # against libcrypto, random inputs
crystal-alpha spec --release --tag constant_time   # timing checks of the hashes, ciphers and curves
/usr/bin/ruby scripts/check_secret_flow.rb FILE.ll # compiled-code check (see docs/crypto/hashes-and-macs.md)
/usr/bin/ruby scripts/fetch_vectors.rb             # re-download the vectors and check their pins
/usr/bin/ruby scripts/fetch_vectors.rb --missing   # install the vectors kept out of git (once, after cloning)
/usr/bin/ruby scripts/generate_field_arithmetic.rb --check # the field arithmetic is fiat-crypto pinned output
/usr/bin/ruby scripts/fetch_certificate_corpus.rb  # the CT corpus for the certificate differential (checked by sha256)
/usr/bin/ruby scripts/update_certificate_data.rb PSL_COMMIT # refresh the Mozilla roots and the Public Suffix List
```

## License

MIT
