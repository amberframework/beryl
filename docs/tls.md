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
| Extensions | SNI, ALPN, supported groups and versions, key share, signature algorithms (and `_cert`), PSK modes (`psk_dhe_ke` only), pre-shared key, cookie, record size limit (answered), GREASE (sent by the client, ignored by the server) |
| Resumption | session tickets sealed with XChaCha20-Poly1305 under the server's ticket key; every resumption runs a fresh ECDHE exchange; the client uses each ticket once |
| Never | 0-RTT data (a server skips refused early data within a budget), renegotiation, compression, TLS 1.2 or older, RSA key exchange, SHA-1 or MD5 signatures, `psk_ke` |

## Limits

Set through `Context#limits = Beryl::TLS::Limits.new(...)`; the defaults are the plan's (§4).

| Limit | Default |
|---|---|
| Ciphertext record | 16,640 bytes (`record_overflow` above) |
| Inner plaintext | 16,385 bytes |
| Handshake message | 64 KiB, refused from its header |
| Server certificate chain | 64 KiB and 10 certificates |
| HelloRetryRequest | one |
| Handshake deadline | 10 seconds, when the IO is a socket |
| KeyUpdate | 32 per minute |
| Warning alerts in a row | 1 (closes CVE-2016-8610's class) |
| Empty records in a row | 32 |
| Refused 0-RTT bytes skipped | 16,384 |
| Client ticket cache | 256 server names, 4 tickets each |

## Seam for the standard library and Amber

The classes are shaped like `OpenSSL::SSL`, so the crystal-alpha fork can alias them under a flag and Amber can use them directly: `Context::Client` (`.insecure`, `ca_certificates=`, `alpn_protocol=`, `verify_mode=`), `Context::Server` (`certificate_chain=`, `private_key=`, `alpn_protocol=`), `Socket::Client.new(io, context, sync_close, hostname)`, `Socket::Server.new(io, context, sync_close, accept)`, `Server` (a `::Socket::Server`, `start_immediately`), and on a socket `alpn_protocol`, `cipher`, `tls_version`, `hostname`, `peer_certificate`. Errors descend from `Beryl::TLS::Error` and carry the alert. `Socket::Server` made with `accept: false` runs its handshake on first use, so an accept loop never waits on a slow client.

## Evidence

- RFC 8448: every secret, key, IV and Finished value of §3 to §5 (`spec/beryl/tls/key_schedule_spec.cr`); every protected record of §3 and §5 (`record_layer_spec.cr`); the client engine reproduces §3's Finished, application data and close_notify records byte for byte from the trace's server flight, the server engine reproduces §3's ServerHello and handshake secrets, and every handshake message of §3 to §7 decodes and re-encodes byte for byte (`rfc8448_handshake_spec.cr`). The trace server key is RSA-1024, which Beryl refuses by design; the specs check its signatures with a spec-only verifier.
- Loopback handshakes for every suite, group and key type, HelloRetryRequest, resumption, ALPN, KeyUpdate, close_notify and each refusal (`handshake_spec.cr`).
