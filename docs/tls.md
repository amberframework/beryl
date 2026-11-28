# TLS 1.3

`Beryl::TLS` is a TLS 1.3 client and server (RFC 9846, the revision of RFC 8446) written in Crystal on Beryl's own cryptography. It links no OpenSSL. It is opt-in until its gates pass for default use (see the plan's GATES row); TLS 1.2 is milestone B6.

## Use

```crystal
require "beryl"

# Client: verifies the chain to the Mozilla roots and the name.
tcp = TCPSocket.new("example.com", 443)
tls = Beryl::TLS::Socket::Client.new(tcp, hostname: "example.com", sync_close: true)
tls << "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
tls.flush
puts tls.gets_to_end

# Server: behind HTTP::Server on stock Crystal.
context = Beryl::TLS::Context::Server.new
context.certificate_chain = "chain.pem" # leaf first
context.private_key = "server.key"      # P-256, RSA 2,048 to 4,096 bits, or Ed25519
context.alpn_protocols = ["http/1.1"]
server = HTTP::Server.new { |http_context| http_context.response.print "hello" }
server.bind(Beryl::TLS::Server.new(TCPServer.new("0.0.0.0", 8443), context))
server.listen
```

`examples/https_server.cr` and `examples/https_client.cr` are complete programs.

## What it speaks

| | Offered and accepted, in order |
|---|---|
| Suites | `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_256_GCM_SHA384` |
| Groups | `x25519`, `secp256r1` (the client sends an `x25519` share; a server that wants `secp256r1` asks with HelloRetryRequest) |
| CertificateVerify | `ecdsa_secp256r1_sha256`, `rsa_pss_rsae_sha256/384/512`, `ed25519`, `ecdsa_secp384r1_sha384` |
| Certificates | the above plus `rsa_pkcs1_sha256/384/512` signatures inside the chain (B4) |
| Extensions | SNI, ALPN, supported groups and versions, key share, signature algorithms (and `_cert`), PSK modes (`psk_dhe_ke` only), pre-shared key, cookie, record size limit (sent by the client with its own limit, answered by the server with its own), GREASE (sent by the client, ignored by the server) |
| Resumption | session tickets sealed with XChaCha20-Poly1305 under the server's ticket key; every resumption runs a fresh ECDHE exchange; the client uses each ticket once |
| Client certificates (server) | off by default; `Context::Server#client_verify_mode=` `Optional` or `Required` sends a CertificateRequest and verifies the client's chain (`clientAuth`) and CertificateVerify; see below |
| Client certificates (client) | sent when the server asks and `Context::Client#certificate_chain=` with `private_key=` (or `certified_key=`) is set; signed with the first scheme the key supports that the CertificateRequest lists; otherwise an empty Certificate; see below |
| Never | 0-RTT data (a server skips refused early data within a budget), renegotiation, compression, TLS 1.2 or older, RSA key exchange, SHA-1 or MD5 signatures, `psk_ke` |

## Client certificates on the client

A client presents a certificate when the server sends a CertificateRequest and its context holds one:

```crystal
context = Beryl::TLS::Context::Client.new
context.certificate_chain = "client-chain.pem" # leaf first
context.private_key = "client.key"             # PKCS #8, SEC 1 or PKCS #1
```

- The client signs CertificateVerify with the first scheme its key supports (P-256 `ecdsa_secp256r1_sha256`, RSA `rsa_pss_rsae_sha256/384/512`, `ed25519`) that the request's `signature_algorithms` lists, using the client context string (RFC 9846 §4.4.3). Certificate and CertificateVerify enter the transcript after the server's Finished and before the client's.
- With no certificate configured, or no scheme in common, the client sends an empty Certificate and the server decides (§4.4.2.4).
- `certificate_authorities` is checked for its form (an empty list is a `decode_error`) and otherwise informational: a configured certificate is sent whatever authorities the server names.
- A chain without its key, or a key without its chain, raises `Beryl::TLS::Error` naming the missing half when a handshake needs the certificate.

## Client certificates on the server

A server asks for client certificates (mutual TLS) when its context says so:

```crystal
context = Beryl::TLS::Context::Server.new
context.certificate_chain = "chain.pem"
context.private_key = "server.key"
context.client_verify_mode = Beryl::TLS::ClientVerifyMode::Required # or Optional
context.client_ca_certificates = "clients-ca.pem"                     # or client_trust_store=

# After the handshake:
socket.peer_certificate.try(&.subject.to_s) # => "CN=alice"
socket.list_of_peer_certificates            # the client's chain, leaf first
```

- `Optional` sends a CertificateRequest, verifies a chain the client sends, and accepts an empty Certificate (no peer certificate). `Required` refuses an empty Certificate with the `certificate_required` alert (RFC 9846 §4.4.2.4). `verify_mode = VerifyMode::Peer` maps to `Required`, as `OpenSSL::SSL::Context::Server` takes it.
- The CertificateRequest has an empty context, lists the CertificateVerify schemes above in `signature_algorithms` (with the `rsa_pkcs1` schemes added in `signature_algorithms_cert`), and names the client trust store's roots in `certificate_authorities` while their names fit in `largest_certificate_authorities_bytesize` (16 KiB).
- The chain goes through `ClientCertificateVerifier`: B4's `ChainVerification` to the client trust store, purpose `clientAuth`, the digitalSignature key usage when present, no name check. Failures map to alerts as on the client: expired `certificate_expired`, no trusted path `unknown_ca`, revoked `certificate_revoked`, anything else `bad_certificate`. A CertificateVerify that does not verify ends the handshake with `decrypt_error`. `client_certificate_verifier=` replaces the verifier. There is no default trust store: a server that asks for client certificates names the authorities that issue them.
- Resumption keeps the identity: a ticket records the client's chain (up to 32 KiB; after a larger chain no tickets are sent), and a resumed connection has the same `peer_certificate`. A server that asks for certificates verifies that chain again when it resumes (a trust store change or an expired leaf gives a full handshake), and one that requires a certificate gives a full handshake to a ticket from a session without one. Tickets sealed by an earlier Beryl (format 1) are not resumed.

## Limits

Set through `Context#limits = Beryl::TLS::Limits.new(...)`; the defaults are the plan's (§4).

| Limit | Default |
|---|---|
| Ciphertext record | 16,640 bytes (`record_overflow` above) |
| Inner plaintext | 16,385 bytes |
| Handshake message | 64 KiB, refused from its header |
| Server certificate chain | 64 KiB and 10 certificates |
| Client certificate chain (server side) | 64 KiB and 10 certificates, the same limits |
| HelloRetryRequest | one |
| Handshake deadline | 10 seconds, when the IO is a socket |
| KeyUpdate | 32 per minute |
| Warning alerts in a row | 1 (closes CVE-2016-8610's class) |
| Empty records in a row | 32 |
| Refused 0-RTT bytes skipped | 16,384 |
| Client ticket cache | 256 server names, 4 tickets each; a ticket is offered only by a context with the same certificate verifier as the connection that received it |
| Records under one sending key | 16,777,216, then an automatic KeyUpdate (`largest_record_count_per_key`; RFC 9846 §5.5) |
| record_size_limit announced | 16,385 (`record_size_limit`, 64 to 16,385); once both ends sent one, a larger record is refused before it is opened (`record_overflow`) |
| Tickets per handshake | 0 to 16 (`Context::Server#session_ticket_count=`) |

## Secrets

Each handshake wipes the secrets it derives when it ends, finished or not:
the (EC)DHE shared secret, the key schedule's stage secrets and the
handshake traffic secrets always, and the application traffic, exporter and
resumption master secrets too when the handshake failed. A connection wipes
its traffic secrets, its exporter and resumption master secrets and its
record IVs when it closes and after any failure; `export_keying_material`
then raises `ConnectionClosed`. Each KeyUpdate wipes the secret and the
record protection it replaces.

An alert that arrives in plaintext while keys are installed (a server
waiting for the client's flight accepts one, since a client that refused
the ServerHello has no keys) is raised as `UnauthenticatedAlert`, a
`PeerAlert` whose message says it may not come from the peer. A
change_cipher_spec record is accepted only after the first ClientHello and
only between handshake messages; a ticket whose issue time lies in the
future is never resumed.

## Seam for the standard library and Amber

The classes are shaped like `OpenSSL::SSL`, so the crystal-alpha fork can alias them under a flag and Amber can use them directly: `Context::Client` (`.insecure`, `ca_certificates=`, `alpn_protocol=`, `verify_mode=`, and `certificate_chain=` with `private_key=` for a client certificate sent when the server asks for one), `Context::Server` (`certificate_chain=`, `private_key=`, `alpn_protocol=`, `verify_mode=`, `client_ca_certificates=`), `Socket::Client.new(io, context, sync_close, hostname)`, `Socket::Server.new(io, context, sync_close, accept)`, `Server` (a `::Socket::Server`, `start_immediately`, and `tcp_nodelay?`, on by default, which sets `TCP_NODELAY` on each accepted `TCPSocket`), and on a socket `alpn_protocol`, `cipher`, `tls_version`, `hostname`, `peer_certificate`. Errors descend from `Beryl::TLS::Error` and carry the alert. `Socket::Server` made with `accept: false` runs its handshake on first use, so an accept loop never waits on a slow client. Sockets that `Server` accepts raise TLS failures from reads and writes as `ConnectionFailed`, an `IO::Error` carrying the TLS error, so `HTTP::Server#bind(Beryl::TLS::Server.new(tcp_server, context))` ends a failed handshake quietly as it does any broken connection (`Socket#is_raising_io_errors=` sets this on any socket).

## Evidence

- RFC 8448: every secret, key, IV and Finished value of §3 to §5 (`spec/beryl/tls/key_schedule_spec.cr`); every protected record of §3 and §5 (`record_layer_spec.cr`); the client engine reproduces §3's Finished, application data and close_notify records byte for byte from the trace's server flight, the server engine reproduces §3's ServerHello and handshake secrets, and every handshake message of §3 to §7 decodes and re-encodes byte for byte (`rfc8448_handshake_spec.cr`). The trace server key is RSA-1024, which Beryl refuses by design; the specs check its signatures with a spec-only verifier.
- Loopback handshakes for every suite, group and key type, HelloRetryRequest, resumption, ALPN, KeyUpdate, close_notify and each refusal (`handshake_spec.cr`).
- Interop: 42 cells against OpenSSL 4.1.0 (`s_client`, `s_server`), curl 8.23.0 and Go 1.27.4's crypto/tls, in both roles, each tool pinned and checked by sha256 (`scripts/interop/`, `TOOLS.md` there; CI job `tls-interop`).
- Fuzzing: `spec/fuzz/tls_handshake_fuzz.cr` mutates recorded handshakes through every decoder and both state machines; 200,000 iterations in CI (`tls-fuzz`).
- BoGo, BoringSSL's TLS test suite at a pinned commit, through `spec/bogo/beryl_bogo_shim.cr` (CI job `tls-bogo`). Every enabled test passes. `spec/bogo/config.json` gives a reason for each disabled test: the test needs TLS 1.2 (B6), a group or feature Beryl does not have, or a behavior where Beryl follows RFC 9846 and BoringSSL is stricter or picks another alert. The shim declines a test (exit 89) that asks for something Beryl does not do and logs the flag that declined it.
- tlsfuzzer's TLS 1.3 scripts at pinned commits against the example server (CI job `tls-tlsfuzzer`), every probe of each script (`-n 0` where a script samples). `scripts/tlsfuzzer/config.json` lists each script's expected failures and each script not run, with a reason for every one.

## Running the gates

```sh
/usr/bin/ruby scripts/interop/install_tools.rb /tmp/interop-tools
/usr/bin/ruby scripts/interop/run_matrix.rb /tmp/interop-tools --report interop-report.md
crystal-alpha build --release spec/fuzz/tls_handshake_fuzz.cr -o tls_handshake_fuzz && ./tls_handshake_fuzz 1000000 SEED
/usr/bin/ruby scripts/bogo/run_bogo.rb /tmp/bogo --report bogo-report.md
/usr/bin/ruby scripts/tlsfuzzer/run_tlsfuzzer.rb /tmp/tlsfuzzer --report tlsfuzzer-report.md
```

Each script fetches its peers at pinned versions and checks them (sha256 for downloads, the commit hash for git checkouts) before it builds anything, and exits 1 on any failure the configs do not explain.
