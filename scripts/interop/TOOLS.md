# Interop peers

`install_tools.rb` installs each peer at the exact version below and checks the download's sha256 before unpacking it. A mismatch stops the run before anything is built. `run_matrix.rb` then runs every cell against Beryl's example server and client (`examples/`).

| Tool | Version | Source | sha256 | Where the hash comes from |
|---|---|---|---|---|
| OpenSSL | 4.1.0 | `https://github.com/openssl/openssl/releases/download/openssl-4.1.0/openssl-4.1.0.tar.gz` | `50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd` | the release's published `.sha256`, equal to GitHub's asset digest |
| curl | 8.23.0 (built against the OpenSSL above) | `https://curl.se/download/curl-8.23.0.tar.xz` | `8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5` | recorded at the first download on 2026-11-24; curl signs its tarballs with GPG and publishes no sha256 file |
| Go | 1.27.4, linux-amd64 | `https://go.dev/dl/go1.27.4.linux-amd64.tar.gz` | `7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840` | go.dev/dl's published checksum |
| Go | 1.27.4, linux-arm64 | `https://go.dev/dl/go1.27.4.linux-arm64.tar.gz` | `3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92` | go.dev/dl's published checksum |
| Go | 1.27.4, darwin-arm64 | `https://go.dev/dl/go1.27.4.darwin-arm64.tar.gz` | `91a44a2b8a716600ad94a4f143e156116620db8828086a6e3602291be9bd0bb4` | go.dev/dl's published checksum |

The Go peer (`go_peer/`) uses only Go's standard library, so it has no module downloads to pin.

## Run

```sh
/usr/bin/ruby scripts/interop/install_tools.rb /tmp/interop-tools
/usr/bin/ruby scripts/interop/run_matrix.rb /tmp/interop-tools --report interop-report.md
```

The matrix exits 1 when any cell fails. CI runs both steps in the `tls-interop` job and keeps no artifacts.

## Cells

Each line lists one group of cells; a cell passes when its output shows the negotiated parameters and the response body.

- **OpenSSL `s_client` to the Beryl server:** each of the three suites; P-256, RSA and Ed25519 leaves; a secp256r1 key share; HelloRetryRequest to secp256r1; ALPN; resumption with a ticket; KeyUpdate with an update requested. In the KeyUpdate cell, `-msg` output must show the KeyUpdate in both directions.
- **curl to the Beryl server:** each suite; each group; ALPN with an Ed25519 leaf.
- **Go client to the Beryl server:** each leaf type with Go's default groups; HelloRetryRequest to secp256r1; ChaCha20-Poly1305 chosen by Beryl; ALPN with resumption.
- **Beryl client to OpenSSL `s_server`:** each suite; each leaf type; HelloRetryRequest to secp256r1; ALPN; resumption; KeyUpdate.
- **Beryl client to the Go server:** each leaf type; HelloRetryRequest to secp256r1; each suite; ALPN with resumption and KeyUpdate.

Updating a pin means changing the version, URL and sha256 together in `install_tools.rb` and in this table, from the publisher's own checksum where one exists.
