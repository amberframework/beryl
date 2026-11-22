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

Available now (milestones B1, B2 and F1 for the hashes): SHA-224, SHA-256, SHA-384, SHA-512 and SHA-512/256; HMAC; HKDF; authenticated encryption with XChaCha20-Poly1305, ChaCha20-Poly1305 and AES-GCM; and, for formats that already exist, MD5, SHA-1, PBKDF2 and AES-CBC. The SHA hashes run on the processor's own SHA instructions on Apple Silicon, Linux AArch64 and Linux x86-64, and on portable code everywhere else. Measured against OpenSSL 4.1.0 on an Apple M1 Max, all 42 hash and HMAC measurements (64 B, 1 KiB and 1 MiB) are at least as fast, with the whole 95% interval on that side; the table is in the document below.

```crystal
require "beryl"

Beryl::Crypto.digest("contents of a file")                             # SHA-256
tag = Beryl::Crypto.authenticate("message", key: secret_key)           # HMAC-SHA256
Beryl::Crypto.verify_authentication("message", tag, key: secret_key)   # => true
Beryl::Crypto.derive_key(shared_secret, info: "cookies", bytesize: 32) # HKDF-SHA256
sealed = Beryl::Crypto.encrypt("message", key: key_of_32_bytes)         # XChaCha20-Poly1305
Beryl::Crypto.decrypt(sealed, key: key_of_32_bytes)                    # => Bytes, or nil if changed
```

The calls on `Beryl::Crypto` always use the algorithm Beryl recommends today. `Beryl::Crypto::V1` names each algorithm exactly, and `Beryl::Crypto::Compatibility` holds the old ones. See [docs/crypto/hashes-and-macs.md](docs/crypto/hashes-and-macs.md) and [docs/crypto/ciphers-and-aeads.md](docs/crypto/ciphers-and-aeads.md) for the full list, the test vectors, how to run each check and the measured speed against OpenSSL.

## Development

```sh
minecart install --frozen
crystal-alpha spec                                 # unit specs and every published vector
crystal-alpha spec -Dberyl_portable_hashes         # the same, on the portable code alone
crystal-alpha spec --release --tag differential    # against libcrypto, random inputs
crystal-alpha spec --release --tag constant_time   # timing check of HMAC
/usr/bin/ruby scripts/check_secret_flow.rb FILE.ll # compiled-code check (see docs/crypto/hashes-and-macs.md)
/usr/bin/ruby scripts/fetch_vectors.rb             # re-download the vectors and check their pins
```

## License

MIT
