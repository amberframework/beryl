# Changelog

## 0.1.0 (2026-11-24)

The first release: cryptography for Amber V2 in pure Crystal. A program
that uses Beryl links no OpenSSL. TLS is not in this release.

- **Hashes and MACs** (#1): SHA-224, SHA-256, SHA-384, SHA-512,
  SHA-512/256, HMAC and HKDF; MD5, SHA-1 and PBKDF2 for existing formats.
  On the processor's SHA instructions where it has them (#3).
- **Ciphers and AEADs** (#2): XChaCha20-Poly1305, ChaCha20-Poly1305 and
  AES-GCM; AES-CBC for existing formats. On the processor's cipher
  instructions where it has them (#4).
- **Public key** (#6, #7): X25519, Ed25519, P-256 ECDSA (RFC 6979 nonces)
  and ECDH, P-384 ECDSA verification, and RSA (PKCS #1 v1.5 and PSS
  signatures, OAEP encryption, 2,048 to 4,096-bit private keys). Field
  arithmetic follows fiat-crypto's output, with assembly on arm64 and
  x86-64 (#11, #13, #14, #15).
- **Certificates** (#10): X.509 parsing and path validation
  (`Beryl::Certificates.verify_server_chain`).
- **Timing:** on Arm every operation on a secret runs with Data Independent
  Timing on (#9); on x86-64 the curve multiplications take fresh operands
  in every window, gated by a two-of-three timing check in CI (#18).
- **One API that picks the algorithm:** `Beryl::Crypto` uses the algorithm
  Beryl recommends today, `Beryl::Crypto::V1` names each one, and
  `Beryl::Crypto::Compatibility` holds the old ones existing formats need.
- **Vendoring:** rooted `::Beryl::` references move under the host's
  namespace when Beryl is vendored (#5).
- Speed against OpenSSL, measured per operation, is in the README and
  `docs/` (#8, #12, #17).
- `Beryl::VERSION` reads 0.1.0.
