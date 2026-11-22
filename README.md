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

Available now (milestone B1): SHA-224, SHA-256, SHA-384, SHA-512 and SHA-512/256; HMAC; HKDF; and, for formats that already exist, MD5, SHA-1 and PBKDF2.

```crystal
require "beryl"

Beryl::Crypto.digest("contents of a file")                             # SHA-256
tag = Beryl::Crypto.authenticate("message", key: secret_key)           # HMAC-SHA256
Beryl::Crypto.verify_authentication("message", tag, key: secret_key)   # => true
Beryl::Crypto.derive_key(shared_secret, info: "cookies", bytesize: 32) # HKDF-SHA256
```

The calls on `Beryl::Crypto` always use the algorithm Beryl recommends today. `Beryl::Crypto::V1` names each algorithm exactly, and `Beryl::Crypto::Compatibility` holds the old ones. See [docs/crypto/hashes-and-macs.md](docs/crypto/hashes-and-macs.md) for the full list, the test vectors and how to run each check.

## Development

```sh
minecart install --frozen
crystal-alpha spec                                 # unit specs and every published vector
crystal-alpha spec --release --tag differential    # against libcrypto, random inputs
crystal-alpha spec --release --tag constant_time   # timing check of HMAC
/usr/bin/ruby scripts/check_secret_flow.rb FILE.ll # compiled-code check (see docs/crypto/hashes-and-macs.md)
/usr/bin/ruby scripts/fetch_vectors.rb             # re-download the vectors and check their pins
```

## License

MIT
