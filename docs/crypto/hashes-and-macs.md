# Hashes, message authentication and key derivation

`Beryl::Crypto` implements these standards in Crystal. Nothing here calls OpenSSL or any other C library.

Status: milestone B1 of the Beryl cryptography plan. The code passes every published vector listed below and agrees with OpenSSL 4.1.0 on millions of random inputs. It passes the three constant-time checks described under "How it is tested". Those gates, not an outside audit, decide when Beryl becomes a default, and every pull request must pass them to merge. It is not tuned for speed yet (hardware SHA instructions arrive in milestone F1).

## Which call to use

Use the calls on `Beryl::Crypto`. They always use the algorithm Beryl recommends today.

```crystal
require "beryl"

# A digest of some bytes: SHA-256, 32 bytes.
digest = Beryl::Crypto.digest(File.read("app.css"))

# Prove a message came from someone who holds the key: HMAC-SHA256, 32 bytes.
tag = Beryl::Crypto.authenticate("user_id=42", key: secret_key)

# Check a tag received from outside. The comparison runs in constant time.
Beryl::Crypto.verify_authentication("user_id=42", tag, key: secret_key) # => true

# Turn one secret into a key for one purpose: HKDF-SHA256.
cookie_key = Beryl::Crypto.derive_key(secret_key, info: "signed cookies", bytesize: 32)
```

When the bytes must stay the same forever (a file format, a protocol, a stored signature), name the algorithm in `Beryl::Crypto::V1` instead, so a later change of the recommended default leaves your output alone.

## What exists

### `Beryl::Crypto::V1`: the named algorithms

| Short name | Full class name | Standard | Digest | Block |
|---|---|---|---|---|
| `SHA224` | `SecureHashWith224BitDigest` | FIPS 180-4 | 28 bytes | 64 bytes |
| `SHA256` | `SecureHashWith256BitDigest` | FIPS 180-4 | 32 bytes | 64 bytes |
| `SHA384` | `SecureHashWith384BitDigest` | FIPS 180-4 | 48 bytes | 128 bytes |
| `SHA512` | `SecureHashWith512BitDigest` | FIPS 180-4 | 64 bytes | 128 bytes |
| `SHA512_256` | `SecureHashWith512BitStateAnd256BitDigest` | FIPS 180-4 | 32 bytes | 128 bytes |
| `HMAC(D)` | `HashBasedMessageAuthenticationCode(D)` | RFC 2104 | as `D` | |
| `HKDF(D)` | `HashBasedKeyDerivationFunction(D)` | RFC 5869 | | |

Every hash is a subclass of the standard library's `::Digest`, so it streams the same way and offers the same class methods:

```crystal
hash = Beryl::Crypto::V1::SHA256.new
hash.update("first part").update("second part")
hash.final      # => Bytes, 32 of them
hash.reset      # ready for another message

Beryl::Crypto::V1::SHA512.hexdigest("abc")
Beryl::Crypto::V1::SHA256::DIGEST_SIZE # => 32
Beryl::Crypto::V1::SHA256::BLOCK_SIZE  # => 64
```

`HMAC(D)` takes the hash as its type argument and streams the same way. `verify` finishes the message and compares in constant time; a tag of the wrong length is refused after the same work as a tag of the right length.

```crystal
authentication = Beryl::Crypto::V1::HMAC(Beryl::Crypto::V1::SHA384).new(key)
authentication.update(header).update(body)
authentication.verify(tag_from_the_request) # => true or false

# A protocol that cuts the tag to its leading bytes (RFC 2104 section 5):
authentication.reset.update(header).update(body)
authentication.verify(short_tag, truncated_to_bytesize: 24)
```

A truncated tag must be at least half the full tag and at least 80 bits; anything shorter raises `Beryl::Crypto::TruncatedTagTooShort`.

`HKDF(D)` works on `SHA256`, `SHA384` and `SHA512`. `derive_key` is the whole function; `extract` and `expand` are its two steps for protocols, such as TLS 1.3, that call them separately. `expand` refuses more than 255 hash outputs with `Beryl::Crypto::DerivedKeyTooLong`.

```crystal
hkdf = Beryl::Crypto::V1::HKDF(Beryl::Crypto::V1::SHA256)
pseudorandom_key = hkdf.extract(shared_secret, salt: salt)
key = hkdf.expand(pseudorandom_key, info: "tls13 key", bytesize: 16)
```

### `Beryl::Crypto::Compatibility`: only for formats that already exist

| Short name | Full class name | Standard | Still needed by |
|---|---|---|---|
| `MD5` | `MessageDigest5` | RFC 1321 | PostgreSQL md5 authentication; lock ids and cache keys that must stay bit-exact |
| `SHA1` | `SecureHashAlgorithm1` | FIPS 180-4 | WebSocket handshakes, UUID v5, MySQL authentication |
| `PBKDF2(D)` | `PasswordBasedKeyDerivationFunction2(D)` | RFC 8018 | PostgreSQL SCRAM-SHA-256 |

MD5 and SHA-1 are broken for collision resistance, and PBKDF2 is not the password hash to choose for a new design. The calls on `Beryl::Crypto` never use them. Where an old algorithm is chosen, the word `Compatibility` appears in the code:

```crystal
Beryl::Crypto::Compatibility::MD5.hexdigest(lock_name)
Beryl::Crypto::V1::HMAC(Beryl::Crypto::Compatibility::SHA1).authenticate(message, key: key)

pbkdf2 = Beryl::Crypto::Compatibility::PBKDF2(Beryl::Crypto::V1::SHA256)
salted_password = pbkdf2.derive_key(password, salt: salt, iteration_count: 4096, bytesize: 32)
```

`PBKDF2(D)` works on `SHA1`, `SHA256` and `SHA512`. `HKDF(D)` also accepts `Compatibility::SHA1`, which the test cases of RFC 5869 itself use.

### Errors

Every error descends from `Beryl::Error` through `Beryl::Crypto::Error`:
`DerivedKeyTooLong`, `DerivedKeySizeIsNegative`, `IterationCountTooSmall`, `MessageTooLong`, `OutputSizeMismatch`, `TruncatedTagTooShort`.

## How it is tested

| Command | What it runs | Time |
|---|---|---|
| `crystal-alpha spec` | Unit specs and every published vector below, with the count per algorithm printed at the end | under a minute |
| `crystal-alpha spec --release --tag slow` | The two PBKDF2 vectors of 16,777,216 iterations | seconds |
| `crystal-alpha spec --release --tag differential` | Beryl against libcrypto on random inputs: 1,000,000 cases per hash and per HMAC (messages of 0 to 65,536 bytes, random `update` splits), 100,000 per HKDF, 10,000 per PBKDF2 (1 to 4,096 iterations). The seed is printed, and any failing case replays alone | about an hour; one algorithm at a time with `-e` |
| `crystal-alpha spec --release --tag constant_time` | Constant time, by timing (the dudect method): HMAC `verify`, keying and tagging, 10,000,000 measurements per class, largest \|t\| under 4.5. Inputs are laid out a batch at a time before any is timed, so the two classes differ only in the secret bytes read | about a minute |
| `valgrind --error-exitcode=99 ./secret_taint` on `spec/probes/secret_taint.cr` (Linux) | Constant time, by memory checker (the ctgrind method): every key, message, tag and password is undefined memory, so Memcheck reports any branch or address computed from one. `./secret_taint leaky` must be reported | seconds |
| `scripts/check_secret_flow.rb` on the LLVM IR of `spec/probes/secret_flow.cr` | Constant time, in the compiled code: follows secrets through the optimized IR of every `Beryl::Crypto` function and reports a branch, a memory index or a division that depends on one. The probe's deliberate leak must be reported | seconds |
| `crystal-alpha build --release -Dwithout_openssl spec/probes/no_libcrypto.cr` then `otool -L` | Proof that the library links no libssl and no libcrypto | seconds |
| `bench/hashes_against_libcrypto.cr` | Baseline speed next to libcrypto, alternating arms | about four minutes |

The differential, the vector pin check and the benchmark are the only places this repository uses OpenSSL. The library requires none of it.

CI (`.github/workflows/ci.yml`) runs the quick suite, the slow vectors, the linkage probe and all three constant-time checks on every pull request. The differential runs on request (`workflow_dispatch`), because it takes about an hour.

The compiled-code check is a taint analysis written for this code, one function at a time, and it was itself tested by planting leaks (an early-exit comparison in `verify`, a secret-dependent `raise` in a compression function, a secret-dependent `break` in PBKDF2): it reported each one. Its header states its limits.

### Published vectors

4,957 cases in all (4,955 in the quick suite, 2 under `--tag slow`).

| Algorithm | NIST CAVP | RFC | Wycheproof |
|---|---|---|---|
| SHA-1 | 229 | | |
| SHA-224 | 229 | | |
| SHA-256 | 229 | | |
| SHA-384 | 357 | | |
| SHA-512 | 357 | | |
| SHA-512/256 | 357 | | |
| MD5 | | 7 (RFC 1321) | |
| HMAC-MD5 | | 7 (RFC 2202) | |
| HMAC-SHA-1 | 300 | 7 (RFC 2202) | 170 |
| HMAC-SHA-224 | 375 | 7 (RFC 4231) | 172 |
| HMAC-SHA-256 | 225 | 7 (RFC 4231) | 174 |
| HMAC-SHA-384 | 300 | 7 (RFC 4231) | 174 |
| HMAC-SHA-512 | 375 | 7 (RFC 4231) | 174 |
| HMAC-SHA-512/256 | | | 175 |
| HKDF-SHA-1 | | 4 (RFC 5869) | 87 |
| HKDF-SHA-256 | | 3 (RFC 5869) | 86 |
| HKDF-SHA-384 | | | 83 |
| HKDF-SHA-512 | | | 83 |
| PBKDF2-HMAC-SHA-1 | | 6 (RFC 6070) | 64 |
| PBKDF2-HMAC-SHA-256 | | 2 (RFC 7914 section 11) | 60 |
| PBKDF2-HMAC-SHA-512 | | | 58 |

Notes on the counts:

- Each SHA row is the short-message file, the long-message file and the 100 Monte Carlo checkpoints. A checkpoint is the result of 1,000 chained digests, so the six Monte Carlo files stand for 600,000 digests.
- The CAVP HMAC cases include tags cut to as few as half the digest; each is checked through `verify` at its stated length, and again with one bit changed, which must be refused.
- Wycheproof: every case marked `valid` is accepted and every case marked `invalid` is rejected. The pinned files hold no case marked `acceptable`; if a later pin adds one, the suite prints Beryl's decision for it after the run.
- MD5 has no CAVP file. It is covered by RFC 1321 appendix A.5 and by the differential.

### Vector sources

Vector files are data, pinned by sha256. `scripts/fetch_vectors.rb` downloads them and refuses any byte that differs from `spec/vectors/manifest.json`; the spec suite checks each file's sha256 again before reading it and fails, naming the file, on any difference. The full list of 38 files with their sha256 is in [`spec/vectors/SOURCES.md`](../../spec/vectors/SOURCES.md). The downloads:

| Source | Download | sha256 |
|---|---|---|
| NIST CAVP, SHA byte-oriented vectors (SHAVS) | https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip | `929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8` |
| NIST CAVP, HMAC vectors | https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip | `418c3837d38f249d6668146bd0090db24dd3c02d2e6797e3de33860a387ae4bd` |
| Wycheproof `testvectors_v1` | https://github.com/C2SP/wycheproof at commit `65ca494727a52944c204441c860b039e6786b99b` (2026-11-11), 13 files | per file, in `SOURCES.md` |
| RFC 1321, 2202, 4231, 5869, 6070, 7914 | https://www.rfc-editor.org/rfc/ | per file, in `SOURCES.md` |

RFC 4231 and RFC 5869 are read field by field from the pinned RFC text. The other four RFCs print their inputs as prose ("0xdd repeated 50 times"), so the specs write those inputs out and first show that each expected output appears in the pinned RFC text.

## Design notes

- **Wrapping arithmetic.** The compression functions use `&+` and the rotations only, so no overflow check runs and no input value decides a branch.
- **Key handling.** `HMAC.new` turns the key into two keyed hash states and wipes its working copies with a volatile write. The key's length is the only thing about it that decides a step. Digest and tag buffers that held secret-dependent values are wiped the same way.
- **Limits.** A message holds at most 2^61 − 1 bytes. HKDF gives at most 255 hash outputs. PBKDF2 runs at least one iteration.
- **Logging.** `Beryl::Log` is the shard's log source. Nothing in `Beryl::Crypto` logs a key, a message or a tag.
