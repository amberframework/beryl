# Changelog

## Unreleased

- A TLS server can ask for client certificates (mutual TLS), off by default.
  `Context::Server#client_verify_mode=` takes `ClientVerifyMode::None`,
  `Optional` (request; verify a chain when one is sent) or `Required` (an
  empty Certificate fails with `certificate_required`); `verify_mode =
  VerifyMode::Peer` maps to `Required`, as OpenSSL's server context takes it.
  Client chains are verified to `client_ca_certificates=` (PEM) or
  `client_trust_store=` by the new `ClientCertificateVerifier` (B4's
  `ChainVerification` with purpose `clientAuth`, digitalSignature key usage,
  no name check); `client_certificate_verifier=` replaces it. The
  CertificateRequest lists the schemes Beryl verifies and the trust store's
  root names (`largest_certificate_authorities_bytesize`, 16 KiB). The
  client's CertificateVerify is checked with the client context string over
  the transcript, and a bad signature ends the handshake with
  `decrypt_error`.
- `Socket::Server#peer_certificate` returns the client's leaf (nil when none
  was asked for or sent), and `#list_of_peer_certificates` (alias
  `#peer_certificate_chain`) the chain.
- Session tickets record the client's chain (ticket format 2; a format 1
  ticket gets a full handshake), so a resumed connection keeps its client
  identity. A server that asks for certificates verifies the chain again on
  resumption, and one that requires a certificate resumes only a session
  that had one.
- BoGo: the shim runs server `-verify-peer`, `-require-any-client-certificate`,
  `-verify-fail`, `-expect-peer-cert-file`, `-expect-verify-result` and an
  empty `-use-client-ca-list`; the TLS 1.3 server client-certificate tests
  run and pass. tlsfuzzer runs `test-tls13-certificate-request.py`,
  `test-tls13-certificate-verify.py`,
  `test-tls13-ecdsa-in-certificate-verify.py` and
  `test-tls13-eddsa-in-certificate-verify.py`. The interop matrix adds
  OpenSSL s_client and the Go client presenting client certificates to the
  example server, which now takes `--client-verify`, `--client-ca` and
  `--any-client-chain`.

## 0.2.2 (2026-11-25)

Memory and polish for HTTPS servers: a `--tls` Amber app under 32 keep-alive
connections peaks at 15.8 to 19.6 MiB, down from 17.6 to 25.2 MiB on 0.2.1.

- A TLS socket keeps about 8 KiB per connection instead of about 103 KiB.
  The record layer reads ahead into its own buffer, sized to the first record
  and doubled only when a larger record arrives, up to the record limits; it
  turns off read buffering on the `IO::Buffered` beneath it. `TLS::Socket`
  reads straight from the opened record, so `IO::Buffered` allocates no read
  buffer, and writes gather in a small growable buffer sealed at `flush`, when
  a record fills, or at `close`. `flush_on_newline` is honored. Handshake
  reassembly storage is released once no message is waiting, and a server
  socket wipes its resumption master secret when the handshake ends (#34).
- `TLS::RecordProtection#wipe` now also zeroes the AEAD's key material:
  AES-GCM's expanded round keys and GHASH key state (H to H^8 on the
  processor instructions), and the ChaCha20-Poly1305 key. Every
  `AuthenticatedEncryption` gains `wipe` and `is_wiped?`; once wiped, every
  encryption, decryption and tag check raises `Crypto::KeyWiped`. The check
  is one branch on public state at each call, outside the per-block loops.
- A certificate signed with SHA-1 (sha1WithRSAEncryption, ecdsa-with-SHA1,
  dsa-with-SHA1) or MD5 is refused by its algorithm identifier, before any
  signature check, with a message that names the hash: "the certificate for
  CN=... is signed with SHA-1, which Beryl refuses (RFC 9155)". The new
  `FailureReason::SignatureAlgorithmRefused` maps to the bad_certificate
  alert in TLS. A SHA-1 CertificateVerify scheme, should one be configured,
  raises with illegal_parameter and the same wording.
- `scripts/fetch_vectors.rb` accepts manifest entries of kind `generated`:
  fixtures made by a script in this repository, committed and pinned by
  sha256 rather than downloaded. The first is
  `spec/vectors/beryl/sha1_signed_chains.pem`, from
  `scripts/generate_sha1_signed_chains.sh` (OpenSSL 4.1.0 pinned by version
  and binary sha256).

## 0.2.1 (2026-11-25)

For the Amber stack's Beryl adoption release: connection pools and private
database CAs.

- Certificate verification accepts a leaf or intermediate without an
  authority key identifier: the issuer is found by name and tried by
  signature, as Go's crypto/x509 and OpenSSL do, so private CAs for
  PostgreSQL and MySQL that omit the extension verify. The path-building
  limits still apply. x509-limbo: `rfc5280::aki::leaf-missing-aki` and
  `rfc5280::aki::intermediate-missing-aki` are now listed as departures,
  with the reason; every other case still matches.
- On macOS, `TrustStore.system` joins the pinned Mozilla roots to
  `/etc/ssl/cert.pem`, unless `SSL_CERT_FILE` is set. The file trails the
  keychain the system actually trusts: macOS 27.2.1's copy lacks SSL.com TLS
  ECC Root CA 2022 and AAA Certificate Services, so clients that use the
  system store (HTTP::Client on Beryl, Grant's PostgreSQL driver,
  crystal-mysql) refused www.example.com. Linux bundles are read as before.
- `TLS::Socket#closed?` answers whether `close` was called, as
  `OpenSSL::SSL::Socket#closed?` does, and `close` is idempotent. Reads and
  writes after `close` raise `IO::Error` ("Closed stream"), so database pools
  and `HTTP::Client` see a closed TLS connection the way they see any other.

## 0.2.0 (2026-11-24)

TLS 1.3, client and server, in pure Crystal. A program that serves or
fetches HTTPS through Beryl links no OpenSSL. TLS 1.3 is the only version
Beryl speaks.

- **TLS 1.3** (#21 to #25): the key schedule and transcript hash, the record
  layer, the client and server state machines, `Beryl::TLS::Context`,
  `Socket` and `Server` shaped like `OpenSSL::SSL`, session tickets and PSK
  resumption (`psk_dhe_ke` only), HelloRetryRequest, ALPN, SNI, KeyUpdate,
  `record_size_limit`, GREASE, and certificate verification through
  `Beryl::Certificates` with name and IP checks against the Mozilla roots
  or a trust store of the program's choosing. Gates: RFC 8448 traces byte
  for byte, BoGo (every applicable TLS 1.3 test), tlsfuzzer's TLS 1.3
  scripts, interop with OpenSSL 4.1.0, curl 8.23.0 and Go 1.27.4 in both
  roles, and a handshake fuzzer, all in CI. Guide: `docs/tls.md`.
- **Security review follow-ups** (#26), from the independent review of the
  TLS code (M4, L1, L2, L3, L5, L6, L8):
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
- **HTTP::Server seam** (#27): sockets accepted by `Beryl::TLS::Server`
  raise TLS failures from reads and writes as `ConnectionFailed < IO::Error`,
  so `HTTP::Server#bind(Beryl::TLS::Server.new(tcp_server, context))` ends a
  client whose handshake fails without an unhandled exception
  (`Socket#is_raising_io_errors=`).
- **Record layer speed (F4, first step)** (#30): each connection reuses its
  record buffers (grown to the largest record seen) instead of allocating
  two per record read and two per record written. On an Amber app over
  HTTPS (wrk, 32 connections, M1 Max) this took requests per second from
  about 65,000 to 79,000 on a small page, ahead of the same app on OpenSSL
  (71,000).
- **System trust store** (#28): `TrustStore.system` reads `SSL_CERT_FILE`,
  as OpenSSL and Go do.
- `Beryl::VERSION` reads 0.2.0.
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
- **HTTP::Server seam** (#27): sockets accepted by `Beryl::TLS::Server`
  raise TLS failures from reads and writes as `ConnectionFailed < IO::Error`,
  so `HTTP::Server#bind(Beryl::TLS::Server.new(tcp_server, context))` ends a
  client whose handshake fails without an unhandled exception
  (`Socket#is_raising_io_errors=`).
- `Beryl::VERSION` reads 0.2.0.

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
