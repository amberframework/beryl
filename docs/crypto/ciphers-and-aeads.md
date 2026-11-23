# Ciphers and authenticated encryption

`Beryl::Crypto` implements these ciphers in Crystal. Nothing here calls OpenSSL or any other C library.

Status: milestones B2 (make it work) and F2 (make it fast) of the Beryl cryptography plan. The code passes every published vector listed below, agrees with OpenSSL 4.1.0 on 8,000,000 random cases, and passes the three constant-time checks described in [hashes-and-macs.md](hashes-and-macs.md). Those gates, not an outside audit, decide when Beryl becomes a default, and every pull request must pass them to merge. Its speed next to OpenSSL 4.1.0 is under "Speed".

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

Each algorithm has two implementations behind the same interface. The processor's own instructions run where it has them; the portable code runs everywhere else, and under `-Dberyl_portable_ciphers`, which the test suite uses to run every vector through it on any machine.

| Processor | AES-GCM and AES-CBC | ChaCha20 | Poly1305 |
|---|---|---|---|
| Apple Silicon (known at compile time) | `aese`/`aesd` and `pmull`, with `eor3` | Advanced SIMD and general registers | 64-bit multiplies (`mul`, `umulh`) |
| Linux on AArch64 (read from the auxiliary vector) | the same when `HWCAP_AES` and `HWCAP_PMULL` are set; `eor3` when `HWCAP_SHA3` is | Advanced SIMD and general registers | 64-bit multiplies |
| x86-64 (read with CPUID) | AES-NI and `pclmulqdq` when present, with SSSE3 and SSE4.1 | SSE2 and SSSE3 | 64-bit multiplies |
| Anywhere else | portable | portable | portable |

- **The instructions.** Crystal has no vector types, so the assembly is written out as inline `asm` statements built by macros (`Armv8CipherInstructions`, `X8664CipherInstructions`). Every statement has at most one branch, which closes its loop on a count of blocks, and reads and writes memory only at fixed offsets from its inputs. AES, carry-less multiply, the vector instructions and the 64-bit multiplies take the same time whatever their operands hold, and `scripts/check_secret_flow.rb` checks each statement's text against that list.
- **AES (portable)** is bitsliced after BearSSL's `aes_ct64`: the S-box is a circuit of AND, OR and XOR over 64-bit words (the Boyar–Peralta circuit), so no table is indexed by a secret byte and no cache line depends on the key or the message.
- **GHASH** with `pmull` or `pclmulqdq` works on byte-reversed blocks and a hash key multiplied by x once, reduces with two carry-less multiplies (Gueron and Kounavis), and hashes sixteen blocks against precomputed powers H to H^16 with one reduction per group. The portable GHASH builds carry-less multiplication from integer multiplies with holes (after BearSSL's `ghash_ctmul64`), again with no table.
- **Poly1305** on 64-bit processors keeps the accumulator in two words and a few bits, with r folded into the product as OpenSSL's `poly1305-armv8` does; a long message is absorbed as four runs side by side and joined with powers of r. The portable code uses three limbs of 44, 44 and 42 bits. Both end in a reduction made of masks.
- **ChaCha20** is additions, XORs and fixed rotations. On AArch64 a pass makes nine blocks: four across the lanes of sixteen vector registers, three more in rows of four registers, and two on the general registers. For sealing and opening long messages, a pass of seven vector blocks absorbs Poly1305 on the general registers at the same time. Short messages run block by block on the general registers.
- **Data Independent Timing.** `encrypt`, `decrypt` and `authentic?` of every AEAD, AES-CBC's `encrypt` and `decrypt`, and the key setup of AES-GCM and AES-CBC run inside `DataIndependentTiming.run`, which turns on the processor's DIT mode (PSTATE.DIT) where it exists and leaves it on for the thread (see [hashes-and-macs.md](hashes-and-macs.md) for why). Without it Arm lets an instruction take a time that depends on its operands.
- **The verdict.** `decrypt` computes the tag, compares it in constant time, and passes the one-bit result through `Declassification.reveal`. That is the only place a secret-derived value decides a branch, and the compiled-code checker lists every such place so a review can see them all.

## How it is tested

`crystal spec` runs the quick suite. The gates are the same as for the hashes; the cipher parts are:

| Gate | Command | What it covers |
|---|---|---|
| Published vectors | `crystal spec` | The table below |
| Differential against libcrypto | `crystal spec --release --tag differential -e "cipher "` | 1,000,000 random cases per cipher: random key, nonce, associated data (0 to 64 bytes) and message (0 to 2,048 bytes, and one in a thousand up to 65,536); Beryl's output must equal libcrypto's, each must open the other's, and a changed copy must be refused by both. AES-GCM includes nonces of 1 to 64 bytes and tags of 12 to 15 bytes; AES-CBC includes altered ciphertexts, where both must agree on whether the padding is valid |
| Timing statistics | `crystal spec --release --tag constant_time` | AES key schedule, AES block encryption and decryption, GHASH, Poly1305, ChaCha20, a forgery against each AEAD (first tag byte wrong against last tag byte wrong), the CBC padding check, and the processor-instruction paths of ChaCha20-Poly1305, XChaCha20-Poly1305, AES-256-GCM and AES-256-CBC on 1 KiB under one fixed key against random keys, each with 10,000,000 measurements per class locally (1,000,000 in CI) |
| Memory checker | CI, Linux | Valgrind with every key, message and intermediate value marked undefined; any branch or index that depends on one is an error. A deliberately leaky probe must be reported |
| Compiled code | `scripts/check_secret_flow.rb` | The LLVM IR of the release build: no branch, memory index or variable-time instruction may depend on a secret, outside the listed declassifications |

The timing check on the processor-instruction paths makes the key the secret class. A check that fixes the message instead cannot pass on Apple Silicon, for any code: on an M1 Max, at 10,000,000 measurements per class, a plain loop that XORs 1 KiB with random bytes gave |t| = 7.94 for one fixed message against random ones, and OpenSSL 4.1.0 gave 12.04 for AES-256-GCM and 7.65 for ChaCha20-Poly1305 (Beryl: 14.27, 8.66). The processor's timing moves with the values of the data it handles, not with any branch or address in the code. The message only ever meets the keystream in an XOR, and the instruction allowlist, Valgrind and the compiled-code checker show that no branch or address depends on it.

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

Every cipher runs on the processor's instructions where it has them (see "How the code avoids leaking secrets"), and on the portable code everywhere else. Measured on an Apple M1 Max with `bench/ciphers_against_libcrypto.cr` against OpenSSL 4.1.0, which uses the same ARMv8 instructions and hand-written NEON: 10 rounds, the two arms taking turns of about 2 MiB within each round until each has used 2 seconds of processor time, with a 16-byte tag and 13 bytes of associated data. Each cell is the median of the rounds; "at least as fast" means the whole paired 95% interval over the rounds is at or above 1.

| Cipher | Direction | 64 B | 1 KiB | 16 KiB | 1 MiB |
|---|---|---|---|---|---|
| ChaCha20-Poly1305 | seal | 1.23× as fast | 1.044× as fast | 1.13× as fast | 1.15× as fast |
| ChaCha20-Poly1305 | open | 1.21× as fast | 1.035× as fast | 1.053× as fast | 1.076× as fast |
| XChaCha20-Poly1305 | seal | 2.01× as fast | 1.31× as fast | 1.16× as fast | 1.16× as fast |
| XChaCha20-Poly1305 | open | 1.93× as fast | 1.3× as fast | 1.098× as fast | 1.063× as fast |
| AES-128-GCM | seal | 1.49× as fast | 1.078× as fast | 1.063× as fast | 1.048× as fast |
| AES-128-GCM | open | 1.27× as fast | 1.049× as fast | 1.054× as fast | 1.053× as fast |
| AES-256-GCM | seal | 1.45× as fast | 1.078× as fast | 1.087× as fast | 1.08× as fast |
| AES-256-GCM | open | 1.24× as fast | 1.04× as fast | 1.068× as fast | 1.07× as fast |

All 32 are at least as fast, with the whole interval on that side. The machine was running other work at the same time (load average 17 to 58); each arm is charged its processor time, not wall time.

libcrypto has no XChaCha20-Poly1305, so that row runs against the construction a program on libcrypto would build: HChaCha20 from one block of libcrypto's raw ChaCha20, then libcrypto's ChaCha20-Poly1305 under the subkey. Both arms must produce the same bytes. Against plain ChaCha20-Poly1305, which skips HChaCha20, Beryl's XChaCha20-Poly1305 is 1.047× and 1.051× slower at 64 B (seal, open), 1.077× and 1.075× slower at 1 KiB, and from 1.049× to 1.15× as fast at 16 KiB and 1 MiB. HChaCha20 is one chain of about 240 dependent instructions that every message pays before anything else can start.

AES-CBC, which does not authenticate:

| Cipher | Direction | 64 B | 1 KiB | 16 KiB | 1 MiB |
|---|---|---|---|---|---|
| AES-128-CBC | encrypt | 1.47× as fast | 1.038× as fast | 1.005× slower | 1.008× slower |
| AES-128-CBC | decrypt | 4.92× as fast | 1.46× as fast | 1.043× slower | 1.073× slower |
| AES-256-CBC | encrypt | 1.29× as fast | 1.005× slower | 1.004× slower | 1.001× as fast |
| AES-256-CBC | decrypt | 3.26× as fast | 1.24× as fast | 1.38× as fast | 1.44× as fast |

CBC encryption is one chain of AES rounds from the first block to the last, so both sides run at the latency of the AES instructions and land within 1% of each other from 16 KiB up. Decryption has no chain and runs eight blocks side by side; for AES-128 at 16 KiB and above, where ten rounds leave little work to overlap, libcrypto's decryption stays 1.043× to 1.073× ahead.

Before this work the ciphers ran only on the portable code. Milestone B2, same machine and benchmark, 10 rounds of 2 seconds:

| Cipher | 64 B | 1 KiB | 16 KiB | 1 MiB |
|---|---|---|---|---|
| ChaCha20-Poly1305 | 1.03× slower | 2.96× slower | 3.6× slower | 3.64× slower |
| AES-128-GCM | 9.3× slower | 34.52× slower | 51.55× slower | 53.14× slower |
| AES-256-GCM | 11.02× slower | 38.99× slower | 54.32× slower | 55.64× slower |

The portable code for the rows B2 did not measure, from a shorter run (3 rounds of 0.5 seconds) of the same benchmark built with `-Dberyl_portable_ciphers`; XChaCha20-Poly1305 against the libcrypto construction above:

| Cipher | Direction | 64 B | 1 KiB | 16 KiB | 1 MiB |
|---|---|---|---|---|---|
| XChaCha20-Poly1305 | seal | 1.53× as fast | 2.08× slower | 3.43× slower | 3.61× slower |
| XChaCha20-Poly1305 | open | 1.48× as fast | 2.13× slower | 3.51× slower | 3.67× slower |
| AES-128-CBC | encrypt | 17.3× slower | 29.92× slower | 30.88× slower | 31.03× slower |
| AES-128-CBC | decrypt | 10.96× slower | 42.8× slower | 73.61× slower | 77.74× slower |
| AES-256-CBC | encrypt | 19.92× slower | 29.62× slower | 30.43× slower | 29.57× slower |
| AES-256-CBC | decrypt | 16.07× slower | 50.47× slower | 51.26× slower | 51.57× slower |

Every log is kept with the pull request that added the processor paths.

## Design notes

- **Decrypt checks first.** No plaintext byte reaches the caller before the tag matches, and a caller's `into:` buffer is left untouched on failure. On AArch64, ChaCha20-Poly1305 decrypts into a scratch buffer while it absorbs the ciphertext, and copies the plaintext out only once the tag is right; the scratch buffer is wiped.
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
