# Ciphers and authenticated encryption

`Beryl::Crypto` implements these ciphers in Crystal. Nothing here calls OpenSSL or any other C library.

Status: milestone B2 of the Beryl cryptography plan. The code passes every published vector listed below, agrees with OpenSSL 4.1.0 on 8,000,000 random cases, and passes the three constant-time checks described in [hashes-and-macs.md](hashes-and-macs.md). Those gates, not an outside audit, decide when Beryl becomes a default, and every pull request must pass them to merge. It is not tuned for speed yet: see "Speed" for the measured gap.

## Which call to use

Use the calls on `Beryl::Crypto`. They always use the algorithm Beryl recommends today, which is XChaCha20-Poly1305.

```crystal
require "beryl"

key = Random::Secure.random_bytes(32)

# Encrypt and authenticate. The result is nonce (24 bytes) | ciphertext | tag (16 bytes),
# with a new random nonce for every call.
sealed = Beryl::Crypto.encrypt("user_id=42", key: key, associated_data: "session cookie")

# Returns the message, or nil when the tag does not match (wrong key, changed
# bytes, or different associated data). Nothing is decrypted before the tag is checked.
Beryl::Crypto.decrypt(sealed, key: key, associated_data: "session cookie") # => Bytes
```

When the bytes must stay the same forever (a file format, a protocol, a stored value), name the algorithm in `Beryl::Crypto::V1` instead, and store the nonce your own way.

## What exists

### `Beryl::Crypto::V1`: the named algorithms

| Short name | Full class name | Standard | Key | Nonce | Tag |
|---|---|---|---|---|---|
| `XChaCha20Poly1305` | `AuthenticatedEncryptionWithExtendedNonceChaCha20AndPoly1305` | draft-irtf-cfrg-xchacha-03 | 32 bytes | 24 bytes | 16 bytes |
| `ChaCha20Poly1305` | `AuthenticatedEncryptionWithChaCha20AndPoly1305` | RFC 8439 | 32 bytes | 12 bytes | 16 bytes |
| `AESGCM` | `AdvancedEncryptionStandardInGaloisCounterMode` | FIPS 197, SP 800-38D | 16, 24 or 32 bytes | any length from 1 byte; 12 bytes recommended | 16 bytes; 15, 14, 13, 12, 8 or 4 on request |

Each is an `AuthenticatedEncryption` (`AEAD` for short) with the same four calls:

```crystal
cipher = Beryl::Crypto::V1::XChaCha20Poly1305.new(key)
sealed = cipher.encrypt(message, nonce: nonce, associated_data: header) # ciphertext | tag
cipher.decrypt(sealed, nonce: nonce, associated_data: header)            # => Bytes or nil
cipher.encrypt(message, into: buffer, nonce: nonce)                      # writes into your buffer
cipher.decrypt(sealed, into: buffer, nonce: nonce)                       # => true or false
```

A nonce must never repeat under one key. A random 24-byte nonce (XChaCha20-Poly1305) is safe for any number of messages. A 12-byte nonce (ChaCha20-Poly1305, AES-GCM) is safe as a counter, or at random for up to about 2^32 messages per key.

The building blocks are public for protocols that need them: `ChaCha20StreamCipher` (with `derive_subkey`, HChaCha20), `Poly1305OneTimeAuthenticator`, `GaloisHash` (GHASH) and `BitslicedAdvancedEncryptionStandard` (the AES block cipher).

### `Beryl::Crypto::Compatibility`: for formats that already exist

| Short name | Full class name | Standard | Use |
|---|---|---|---|
| `AESCBC` | `AdvancedEncryptionStandardInCipherBlockChainingMode` | FIPS 197, SP 800-38A, PKCS#7 padding | Reading values written as AES-CBC, such as Amber's version 1 cookies and Grant's version 1 encrypted attributes |

AES-CBC does not authenticate. Check an HMAC over the ciphertext first, as those formats do, and only then decrypt. `decrypt` returns nil for invalid padding, and it checks the padding without a branch on any padding byte.

## How the code avoids leaking secrets

- **AES** is bitsliced after BearSSL's `aes_ct64`: the S-box is a circuit of AND, OR and XOR over 64-bit words (the Boyar–Peralta circuit), so no table is indexed by a secret byte and no cache line depends on the key or the message.
- **GHASH** multiplies in GF(2^128) with carry-less multiplication built from integer multiplies with holes (after BearSSL's `ghash_ctmul64`), again with no table.
- **Poly1305** uses three limbs of 44, 44 and 42 bits with 128-bit products, and a final reduction made of masks.
- **ChaCha20** is additions, XORs and fixed rotations.
- **The verdict.** `decrypt` computes the tag, compares it in constant time, and passes the one-bit result through `Declassification.reveal`. That is the only place a secret-derived value decides a branch, and the compiled-code checker lists every such place so a review can see them all.

## How it is tested

`crystal spec` runs the quick suite. The gates are the same as for the hashes; the cipher parts are:

| Gate | Command | What it covers |
|---|---|---|
| Published vectors | `crystal spec` | The table below |
| Differential against libcrypto | `crystal spec --release --tag differential -e "cipher "` | 1,000,000 random cases per cipher: random key, nonce, associated data (0 to 64 bytes) and message (0 to 2,048 bytes, and one in a thousand up to 65,536); Beryl's output must equal libcrypto's, each must open the other's, and a changed copy must be refused by both. AES-GCM includes nonces of 1 to 64 bytes and tags of 12 to 15 bytes; AES-CBC includes altered ciphertexts, where both must agree on whether the padding is valid |
| Timing statistics | `crystal spec --release --tag constant_time` | AES key schedule, AES block encryption and decryption, GHASH, Poly1305, ChaCha20, a forgery against each AEAD (first tag byte wrong against last tag byte wrong) and the CBC padding check, each with 10,000,000 measurements per class locally (1,000,000 in CI) |
| Memory checker | CI, Linux | Valgrind with every key, message and intermediate value marked undefined; any branch or index that depends on one is an error. A deliberately leaky probe must be reported |
| Compiled code | `scripts/check_secret_flow.rb` | The LLVM IR of the release build: no branch, memory index or variable-time instruction may depend on a secret, outside the listed declassifications |

### Published vectors

57,677 cases in the quick suite across Beryl, 52,722 of them for the ciphers:

| Algorithm | NIST CAVP | RFC or draft | Wycheproof |
|---|---|---|---|
| AES block cipher (128, 192, 256) | 2,138 | | |
| AES-CBC | 2,138 | | 216 |
| AES-GCM | 47,250 | | 316 |
| ChaCha20 | | 8 (RFC 8439) | |
| Poly1305 | | 12 (RFC 8439) | |
| ChaCha20-Poly1305 | | 2 (RFC 8439) | 325 |
| HChaCha20 | | 1 (draft-irtf-cfrg-xchacha-03) | |
| XChaCha20-Poly1305 | | 1 (draft-irtf-cfrg-xchacha-03) | 315 |

Every Wycheproof case marked `valid` is accepted and every case marked `invalid` is rejected; the pinned files hold no case marked `acceptable`. Vector files are pinned by sha256 in `spec/vectors/manifest.json`, and the full list is in [`spec/vectors/SOURCES.md`](../../spec/vectors/SOURCES.md).

## Speed

Step one was to make it correct and constant-time; step two (milestone F1) makes it fast. Measured on an Apple M1 Max with `bench/ciphers_against_libcrypto.cr` (10 rounds, Beryl then libcrypto in each, 2 seconds per arm) against OpenSSL 4.1.0, which uses the ARMv8 AES and polynomial-multiply instructions and hand-written NEON:

| Cipher | 64 B | 1 KiB | 16 KiB | 1 MiB |
|---|---|---|---|---|
| ChaCha20-Poly1305 | 1.0× as fast | 2.67× slower | 3.64× slower | 3.73× slower |
| AES-128-GCM | 9.29× slower | 33.16× slower | 51.03× slower | 54.11× slower |
| AES-256-GCM | 11.28× slower | 38.61× slower | 47.53× slower | 54.6× slower |

The machine was busy with other work during the run (load average near 90), so treat each figure as approximate; the rounds for one cell spread by up to a factor of two. In absolute terms Beryl's ChaCha20-Poly1305 moved 206 to 291 MB/s, and its AES-GCM 34 to 139 MB/s. A session cookie is at most 4 KiB, which at those rates is about 15 to 20 microseconds of ChaCha20-Poly1305. The AES gap is the cost of portable bitsliced code against hardware AES; F1 adds the hardware instructions behind the same interface and the same gates.

## Design notes

- **Decrypt checks first.** No plaintext byte is produced before the tag matches, and a caller's `into:` buffer is left untouched on failure.
- **XChaCha20-Poly1305** derives a subkey with HChaCha20 for every message, then runs ChaCha20-Poly1305 with the last 8 nonce bytes.
- **AES-GCM** accepts a nonce of any length as SP 800-38D defines it (a 12-byte nonce is used directly; any other is hashed with GHASH). A Crystal `Bytes` holds under 2^31 bytes, which is inside GCM's limit of 2^36 − 32 bytes for one message.
- **Errors.** A key, nonce or tag size that the algorithm does not accept raises `KeySizeMismatch`, `NonceSizeMismatch` or `TagSizeNotSupported`, each a `Beryl::Error`. A tag that does not match is never an exception: `decrypt` returns nil or false.
- **Wiping.** The Poly1305 one-time key, the GHASH working state, computed tags, keystream blocks and padded plaintext are wiped with a volatile write when the call is done with them. A cipher object keeps its key (and for AES its round keys) for as long as it lives.

## Carrying a pinned copy in another library

A library that cannot name Beryl as a dependency carries a pinned copy made by `scripts/vendor_into.rb`: the source at one commit, moved under the library's namespace (`Amber::Beryl`, `Grant::Beryl`), with a manifest of the commit and each file's sha256. The copy is never edited in place; `--check` and a spec in the carrying library recompute every hash.

```
/usr/bin/ruby scripts/vendor_into.rb --commit COMMIT --namespace Amber --destination ../amber/src/amber/vendor
/usr/bin/ruby scripts/vendor_into.rb --check --destination ../amber/src/amber/vendor
```
