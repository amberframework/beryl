# Hashes, message authentication and key derivation

`Beryl::Crypto` implements these standards in Crystal. Nothing here calls OpenSSL or any other C library.

Status: milestones B1 (make it work) and F1 (make it fast) of the Beryl cryptography plan. The code passes every published vector listed below and agrees with OpenSSL 4.1.0 on millions of random inputs. It passes the three constant-time checks described under "How it is tested". Those gates, not an outside audit, decide when Beryl becomes a default, and every pull request must pass them to merge. Its speed next to OpenSSL 4.1.0 is under "Speed".

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

## Speed

Every SHA hash runs on the processor's own SHA instructions where the processor has them, and on portable Crystal everywhere else. `Beryl::Crypto::ProcessorFeatures` makes the choice once, when the program starts.

| Platform | SHA-1, SHA-224, SHA-256 | SHA-384, SHA-512, SHA-512/256 | How the processor is asked |
|---|---|---|---|
| Apple Silicon (macOS on AArch64) | ARMv8 SHA1 and SHA2 instructions | ARMv8.2 SHA512 instructions | Every Apple Silicon processor has them; known at compile time |
| Linux on AArch64 | ARMv8 SHA1 and SHA2 instructions | ARMv8.2 SHA512 instructions | `getauxval(AT_HWCAP)`, each of the three on its own bit |
| Linux on x86-64 | SHA extensions (SHA-NI) | portable code | CPUID |
| Anything else, or built with `-Dberyl_portable_hashes` | portable code | portable code | |

MD5 is portable code on every platform; no processor has MD5 instructions.

Measured against OpenSSL 4.1.0 on an Apple M1 Max, which runs the same ARMv8 instructions in OpenSSL's own assembly (`bench/hashes_against_libcrypto.cr`, 2026-11-22). A row is ten rounds (rows whose first interval spanned 1 were measured again with 20 or 30 rounds, and the table shows the longer run); in a round each arm runs for two seconds of processor time, the two arms taking turns of a few milliseconds on the same buffer. "Paired 95% interval" is the interval of the per-round ratio. HMAC is keyed once and restarted for each message on both sides.

| Algorithm | Message | Beryl MB/s | libcrypto MB/s | Beryl against libcrypto (median of rounds) | Paired 95% interval | At least as fast |
|---|---|---|---|---|---|---|
| MD5 | 64 B | 333.9 | 243.2 | 1.37× as fast | 1.37× as fast to 1.38× as fast | yes |
| MD5 | 1 KiB | 622.4 | 595.4 | 1.045× as fast | 1.044× as fast to 1.047× as fast | yes |
| MD5 | 1 MiB | 666.5 | 664.1 | 1.004× as fast | 1.003× as fast to 1.005× as fast | yes |
| HMAC-MD5 | 64 B | 220.4 | 218.0 | 1.011× as fast | 1.01× as fast to 1.012× as fast | yes |
| HMAC-MD5 | 1 KiB | 590.3 | 588.5 | 1.003× as fast | 1.002× as fast to 1.003× as fast | yes |
| HMAC-MD5 | 1 MiB | 665.6 | 663.4 | 1.003× as fast | 1.002× as fast to 1.004× as fast | yes |
| SHA-1 | 64 B | 1011.1 | 386.9 | 2.62× as fast | 2.61× as fast to 2.62× as fast | yes |
| SHA-1 | 1 KiB | 2102.9 | 1775.2 | 1.18× as fast | 1.18× as fast to 1.19× as fast | yes |
| SHA-1 | 1 MiB | 2250.6 | 2247.7 | 1.001× as fast | 1.001× as fast to 1.002× as fast | yes |
| HMAC-SHA-1 | 64 B | 676.0 | 492.7 | 1.37× as fast | 1.37× as fast to 1.38× as fast | yes |
| HMAC-SHA-1 | 1 KiB | 1977.7 | 1916.0 | 1.033× as fast | 1.032× as fast to 1.033× as fast | yes |
| HMAC-SHA-1 | 1 MiB | 2216.2 | 2214.5 | 1.0× as fast | 1.0× as fast to 1.001× as fast | yes |
| SHA-224 | 64 B | 1020.9 | 424.0 | 2.41× as fast | 2.4× as fast to 2.41× as fast | yes |
| SHA-224 | 1 KiB | 2134.3 | 1844.7 | 1.16× as fast | 1.16× as fast to 1.16× as fast | yes |
| SHA-224 | 1 MiB | 2309.9 | 2306.3 | 1.002× as fast | 1.001× as fast to 1.002× as fast | yes |
| HMAC-SHA-224 | 64 B | 691.3 | 560.8 | 1.23× as fast | 1.23× as fast to 1.23× as fast | yes |
| HMAC-SHA-224 | 1 KiB | 1978.1 | 1944.4 | 1.017× as fast | 1.016× as fast to 1.018× as fast | yes |
| HMAC-SHA-224 | 1 MiB | 2363.1 | 2362.8 | 1.001× as fast | 1.0× as fast to 1.001× as fast | yes |
| SHA-256 | 64 B | 1050.6 | 406.6 | 2.59× as fast | 2.58× as fast to 2.59× as fast | yes |
| SHA-256 | 1 KiB | 2266.3 | 1892.4 | 1.2× as fast | 1.2× as fast to 1.2× as fast | yes |
| SHA-256 | 1 MiB | 2283.1 | 2278.3 | 1.002× as fast | 1.001× as fast to 1.004× as fast | yes |
| HMAC-SHA-256 | 64 B | 660.5 | 564.8 | 1.18× as fast | 1.17× as fast to 1.18× as fast | yes |
| HMAC-SHA-256 | 1 KiB | 1978.6 | 1952.3 | 1.015× as fast | 1.013× as fast to 1.016× as fast | yes |
| HMAC-SHA-256 | 1 MiB | 2209.6 | 2206.7 | 1.001× as fast | 1.0× as fast to 1.002× as fast | yes |
| SHA-384 | 64 B | 641.0 | 329.1 | 1.95× as fast | 1.94× as fast to 1.96× as fast | yes |
| SHA-384 | 1 KiB | 1147.6 | 1029.4 | 1.12× as fast | 1.11× as fast to 1.12× as fast | yes |
| SHA-384 | 1 MiB | 1337.7 | 1322.7 | 1.012× as fast | 1.01× as fast to 1.014× as fast | yes |
| HMAC-SHA-384 | 64 B | 311.6 | 278.6 | 1.11× as fast | 1.11× as fast to 1.12× as fast | yes |
| HMAC-SHA-384 | 1 KiB | 1058.4 | 1028.5 | 1.023× as fast | 1.023× as fast to 1.029× as fast | yes |
| HMAC-SHA-384 | 1 MiB | 1338.1 | 1320.1 | 1.011× as fast | 1.008× as fast to 1.013× as fast | yes |
| SHA-512 | 64 B | 631.5 | 309.8 | 2.03× as fast | 2.02× as fast to 2.04× as fast | yes |
| SHA-512 | 1 KiB | 1161.8 | 1043.4 | 1.12× as fast | 1.11× as fast to 1.12× as fast | yes |
| SHA-512 | 1 MiB | 1353.1 | 1331.0 | 1.014× as fast | 1.013× as fast to 1.016× as fast | yes |
| HMAC-SHA-512 | 64 B | 305.1 | 284.2 | 1.073× as fast | 1.066× as fast to 1.077× as fast | yes |
| HMAC-SHA-512 | 1 KiB | 1078.1 | 1056.1 | 1.019× as fast | 1.018× as fast to 1.021× as fast | yes |
| HMAC-SHA-512 | 1 MiB | 1349.2 | 1335.1 | 1.011× as fast | 1.011× as fast to 1.013× as fast | yes |
| SHA-512/256 | 64 B | 642.2 | 320.6 | 2.01× as fast | 2.0× as fast to 2.02× as fast | yes |
| SHA-512/256 | 1 KiB | 1193.6 | 1072.8 | 1.11× as fast | 1.11× as fast to 1.12× as fast | yes |
| SHA-512/256 | 1 MiB | 1326.8 | 1308.5 | 1.014× as fast | 1.012× as fast to 1.015× as fast | yes |
| HMAC-SHA-512/256 | 64 B | 334.1 | 290.9 | 1.15× as fast | 1.14× as fast to 1.15× as fast | yes |
| HMAC-SHA-512/256 | 1 KiB | 1084.1 | 1067.8 | 1.018× as fast | 1.015× as fast to 1.019× as fast | yes |
| HMAC-SHA-512/256 | 1 MiB | 1349.5 | 1333.4 | 1.012× as fast | 1.01× as fast to 1.013× as fast | yes |

How to read it:

- **42 of 42 rows are faster than OpenSSL with the whole interval above 1.** At 64 B and 1 KiB the gain is in what surrounds the compression function: Beryl's `reset`, `update` and `final` do less work per message than OpenSSL's, and HMAC keeps its outer block laid out.
- **On 1 MiB messages SHA-1, SHA-224 and SHA-256 lead by at most 0.4%.** Both libraries run the same ARMv8 instructions there, each group of four rounds waits for the one before it, and that chain sets the speed of both. The HMAC-SHA-1 and HMAC-SHA-224 rows at 1 MiB first came out as ties in a ten-round run and are shown from the longer runs; every run is kept with the evidence.
- SHA-384, SHA-512 and SHA-512/256 are ahead on long messages too, because Beryl's SHA-512 routine gives `sha512h` a sum that already holds c and d and so takes one addition out of the chain between rounds.

The portable code was not measured against OpenSSL here, because on this processor OpenSSL keeps its SHA instructions. In a best-case timing of 64 KiB messages it runs SHA-1 at 0.41, SHA-256 at 0.14 and SHA-512 at 0.39 of the speed of OpenSSL with the instructions; this work made portable SHA-256 12% and portable SHA-512 18% faster than they were.

## How it is tested

| Command | What it runs | Time |
|---|---|---|
| `crystal-alpha spec` | Unit specs and every published vector below, with the count per algorithm printed at the end, on the code the processor selects | under a minute |
| `crystal-alpha spec -Dberyl_portable_hashes` | The same suite with every hash on its portable code, whatever the processor has | under a minute |
| `crystal-alpha spec --release --tag slow` | The two PBKDF2 vectors of 16,777,216 iterations | seconds |
| `crystal-alpha spec --release --tag differential` | Beryl against libcrypto on random inputs: 1,000,000 cases per hash and per HMAC (messages of 0 to 65,536 bytes, random `update` splits), 100,000 per HKDF, 10,000 per PBKDF2 (1 to 4,096 iterations). The seed is printed, and any failing case replays alone | one to two hours of processor time; one algorithm at a time with `-e` |
| `crystal-alpha spec --release --tag constant_time` | Constant time, by timing (the dudect method): HMAC `verify`, keying and tagging, 10,000,000 measurements per class, largest \|t\| under 4.5. Inputs are laid out a batch at a time before any is timed, so the two classes differ only in the secret bytes read | about a minute |
| `valgrind --error-exitcode=99 ./secret_taint` on `spec/probes/secret_taint.cr` (Linux) | Constant time, by memory checker (the ctgrind method): every key, message, tag and password is undefined memory, so Memcheck reports any branch or address computed from one. `./secret_taint leaky` must be reported | seconds |
| `scripts/check_secret_flow.rb` on the LLVM IR of `spec/probes/secret_flow.cr` | Constant time, in the compiled code: follows secrets through the optimized IR of every `Beryl::Crypto` function and reports a branch, a memory index or a division that depends on one. The probe's deliberate leak must be reported | seconds |
| `crystal-alpha build --release -Dwithout_openssl spec/probes/no_libcrypto.cr` then `otool -L` | Proof that the library links no libssl and no libcrypto | seconds |
| `bench/hashes_against_libcrypto.cr` | Speed of every hash and HMAC next to libcrypto, alternating arms (see "Speed") | 40 seconds per row, 28 minutes for all 42; `BERYL_BENCH_ALGORITHMS` picks some |

The differential, the vector pin check and the benchmark are the only places this repository uses OpenSSL. The library requires none of it.

CI (`.github/workflows/ci.yml`) runs the quick suite (on the code the processor selects, then on the portable code alone), the slow vectors, the linkage probe and all three constant-time checks on every pull request, on Linux x86-64, and the suite, the memory-checker run and the compiled-code check again on Linux AArch64. The differential runs on request (`workflow_dispatch`), because it takes one to two hours; it then runs three times: on Linux x86-64 with the code the processor selects, on Linux x86-64 with the portable code alone, and on Linux AArch64.

The compiled-code check is a taint analysis written for this code, one function at a time, and it was itself tested by planting leaks (an early-exit comparison in `verify`, a secret-dependent `raise` in a compression function, a secret-dependent `break` in PBKDF2): it reported each one. Assembly is opaque to that analysis, so the checker reads its text instead: every instruction must be on a list of instructions whose timing does not depend on their operands, the only conditional branch must close the loop on the count of blocks, and memory may be addressed only as a register plus a constant. That rule was tested the same way (a branch on a data register, a load indexed by a register, a division, a second write to the counting register): it reported each one. Its header states its limits.

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
- **Processor instructions.** `Beryl::Crypto::ProcessorFeatures` decides once, when the program starts, whether each hash runs on the processor's SHA instructions; the assembly lives in `armv8_hash_instructions.cr` and `x86_64_hash_instructions.cr`. It has one branch, on the count of blocks left, and reads memory only at fixed offsets, so it keeps the constant-time rules by construction. The portable code is always compiled in and is the same code the vectors run on under `-Dberyl_portable_hashes`.
- **Key handling.** `HMAC.new` turns the key into two keyed hash states and wipes its working copies with a volatile write. The key's length is the only thing about it that decides a step. Digest and tag buffers that held secret-dependent values are wiped the same way.
- **Data Independent Timing.** HMAC (keying, `update`, `final`, `authenticate`, `verify`), HKDF and PBKDF2 run inside `DataIndependentTiming.run`, which turns on the processor's DIT mode (PSTATE.DIT, Armv8.4) where it exists and leaves it on for the thread. Without it Arm lets an instruction take a time that depends on its operands, and Apple M4 does so (measured on X25519, see [public-key.md](public-key.md)). Turning the mode off after each call would cost about 17 ns on M4, half of SHA-256 on 64 bytes, while HMAC-SHA-256 and SHA-256 were measured no slower with it on; a call that finds it on pays about 0.5 ns to check. x86-64 runs the code as it is. A plain hash does not turn the mode on itself, since what it hashes is usually public; a program that hashes a secret can use HMAC or HKDF, which do.
- **Limits.** A message holds at most 2^61 − 1 bytes. HKDF gives at most 255 hash outputs. PBKDF2 runs at least one iteration.
- **Logging.** `Beryl::Log` is the shard's log source. Nothing in `Beryl::Crypto` logs a key, a message or a tag.
