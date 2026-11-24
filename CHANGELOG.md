# Changelog

## Unreleased

- **TLS security review follow-ups** (review of fa2cd41, items M4, L1, L2,
  L3, L5, L6, L8):
  - Handshakes wipe every secret they derive in an `ensure`, including on
    failure; connections wipe the traffic, exporter and resumption master
    secrets and the record IVs at close and after a failure (M4).
  - A plaintext alert read while keys are installed raises
    `UnauthenticatedAlert` instead of passing as the peer's alert (L1).
  - Duplicate extensions and key shares are found with sets, so a
    ClientHello of many entries is checked in linear time (L2).
  - change_cipher_spec is refused before the first ClientHello and between
    the fragments of a handshake message (L3).
  - A ticket issued in the future is never resumed (L5).
  - A client ticket records the certificate verifier of its connection and
    is offered only by a context with the same verifier (L6).
  - A sending key moves on with an automatic KeyUpdate after
    `Limits#largest_record_count_per_key` records (16,777,216 by default);
    `Context::Server#session_ticket_count=` accepts 0 to 16 (L8).
  - The client sends its own `record_size_limit` (RFC 8449) and the server
    answers with its own; both come from `Limits#record_size_limit` and
    are enforced on what each end reads once both sent one.

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
