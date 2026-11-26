# Public-key cryptography

`Beryl::Crypto` implements these standards in Crystal. Nothing here calls OpenSSL or any other C library.

Status: milestone B3 (make it work) of the Beryl cryptography plan, and milestone F3 (speed: assembly field and RSA arithmetic on AArch64). Each section below lists the published vectors the code passes, its differential against OpenSSL, and its three constant-time checks. Those gates, not an outside audit, decide when Beryl becomes a default, and every pull request must pass them to merge.

## Elliptic curves

| Name | Module | Operations | Standard |
|---|---|---|---|
| `X25519` | `DiffieHellmanOverCurve25519` | key agreement | RFC 7748 |
| `Ed25519` | `EdwardsCurveSignaturesOverCurve25519` | signing and verification (pure Ed25519) | RFC 8032 |
| `P256` | `EllipticCurveP256` | ECDSA signing (RFC 6979 nonces) and verification, ECDH | FIPS 186-5, SP 800-186, RFC 6979, SEC 1 |
| `P384` | `EllipticCurveP384` | ECDSA verification | FIPS 186-5, SP 800-186 |

```crystal
require "beryl"

# The recommended choices: Ed25519 to sign, X25519 to agree on a secret.
signing_key = Beryl::Crypto.generate_signing_key
signature = Beryl::Crypto.sign("a message", signing_key: signing_key)
Beryl::Crypto.verify_signature("a message", signature, verification_key: signing_key.verification_key) # => true

alice = Beryl::Crypto.generate_key_agreement_key
bob = Beryl::Crypto.generate_key_agreement_key
Beryl::Crypto.agree_on_shared_secret(alice, bob.public_key) # => 32 bytes, or nil for a peer key of small order

# P-256, for TLS and certificates. Signatures are DER by default; FixedWidth is r || s (COSE, JOSE, WebCrypto).
alias P256 = Beryl::Crypto::V1::P256
private_key = P256::PrivateKey.generate
der_signature = private_key.sign("a message")
private_key.public_key.verify("a message", der_signature) # => true
P256::PublicKey.new(private_key.public_key.to_compressed)   # SEC 1 points, compressed or uncompressed
```

Bytes that are not a key raise `Beryl::Crypto::InvalidPublicKey` or `InvalidPrivateKey`; a key of the wrong length raises `KeySizeMismatch`. Verification returns `false` for any signature it does not accept, including malformed encodings.

### Choices that differ from some other libraries

- **Ed25519 verification is cofactorless and strict:** S must be below L, A and R must be canonical encodings (y < p). The check is encode([S]B + [k](-A)) == R, negating the point as ref10 and OpenSSL do, so a key with a small-order component gets the same verdict as in OpenSSL on every Wycheproof case.
- **ECDSA signatures are strict DER:** short length forms only, minimal positive INTEGERs, nothing after the SEQUENCE.
- **Hybrid points (prefix 0x06 or 0x07) are refused**, as RFC 5480 §2.2 requires; OpenSSL reads them. The differential checks that Beryl refuses each one and that OpenSSL's verdict equals Beryl's on the same point written uncompressed.
- **P-256 signing is deterministic** (RFC 6979 with HMAC over the curve's hash), so a broken random source cannot leak the key through a repeated nonce.
- **P-384 is verification only** (certificate chains need it); signing waits for a user.

### How the code avoids leaking secrets

- **Field arithmetic is fiat-crypto's** (machine-checked correct and branch-free): `scripts/generate_field_arithmetic.rb` translates fiat-crypto's pinned JSON output (commit `3d2880ef`, sha256 checked) into `src/beryl/crypto/field_arithmetic/`, and `--check` proves the files match. A program compares every translated function with fiat-crypto's own C on 100,000,000 inputs each.
- **Field arithmetic in assembly** (milestone F3): on AArch64 the P-256 field (multiplication, squaring, addition, subtraction, negation), the P-256 group order and the P-384 field and order (multiplication and squaring) run in inline assembly written out by macros in `src/beryl/crypto/field_arithmetic/fields_in_assembly.cr`, and on x86-64 the P-256 field multiplication and squaring (`mulq`/`adcq`); other processors run fiat-crypto's code. (The x86-64 multiplication first named its flags clobber "cc", which LLVM ignores on x86-64, where the name is "flags". In `--release` builds the scheduler then placed it between the `subq` and the `sbbq` of fiat-crypto's subtraction, so point additions and ECDH came out wrong while the multiplication alone stayed right. `scripts/check_secret_flow.rb` now refuses any assembly that writes the flags without its processor's clobber name.) Montgomery multiplication word by word has one result for every input, so the assembly must return fiat-crypto's output bit for bit, and the equality program checks that it does on the same 100,000,000 inputs per function (CI runs 1,000,000). The assembly has no branch and no address computed from data; `-Dberyl_portable_curves` builds fiat-crypto's code alone, and CI runs the suite both ways. Apple M4 runs about three flag-setting instructions per cycle against two multiplications, and the curve code is limited by the flags, so the AArch64 P-256 code spends them sparingly (milestone F3b): the Montgomery reduction forms w·(2^64 − 2^32 + 1) with `mul` and `umulh`, the squaring doubles its cross products with `extr`, and a field halving (`half`, a/2 mod p in five flag-setting instructions) lets the point doubling follow OpenSSL's `ecp_nistz256_point_double` with 10 additions and one halving instead of 14 additions. `half` has no fiat-crypto counterpart; the equality program checks that fiat-crypto's C `add` gives back a from half(a) + half(a), for inputs below p (the only ones the curve code passes), and that the assembly equals the portable Crystal halving bit for bit.
- **Inversion** on P-256 (modulo p and modulo the group order) and modulo 2^255 − 19 uses the divsteps of Bernstein and Yang, as libsecp256k1's constant-time `secp256k1_modinv64` writes them (`src/beryl/crypto/field_arithmetic/divstep_inversion.cr`): ten rounds of 59 divsteps, enough for any 256-bit input, each decision a mask. It takes about 1.1 µs on M4 where Fermat's exponentiation took 1.8 to 3.6 µs; a spec compares the two on 20,000 random values and the edge values per modulus. P-384 keeps Fermat.
- **X25519** is the Montgomery ladder of RFC 7748 with a masked swap, started from projective coordinates scaled by a random factor (the same points, new intermediate values on every call). Public keys come from the edwards25519 tables below, mapped by u = (Z + Y) / (Z - Y), which equals the ladder on u = 9.
- **Ed25519** uses the complete addition formulas of RFC 8032, so no input takes a special branch; a secret scalar is processed four bits at a time and every table lookup reads all 16 entries.
- **P-256 and P-384** use Jacobian coordinates (dbl-2001-b and add-1998-cmo-2 for a = -3), with infinity handled by masks. Those formulas are wrong only when both operands are the same point, and each constant-time caller shows that it never adds a point to itself: a secret scalar is written in signed 5-bit windows (Booth's recoding, as in OpenSSL's nistz256), and before window i is added the running sum is [32·H]P with 0 < 32·H − d < n, so the operands differ. Every table lookup reads all 16 entries; on AArch64 it does so on the vector registers, merging each entry under a mask with `bit`.
- **Fixed-base multiplication** ([k]G, [k]B) uses one precomputed table per window (4 bits for edwards25519; for P-256 and P-384, signed 5-bit digits that are all odd, from -31 to 31, over tables of the odd multiples, affine points), so it needs no doubling between windows, with the same full scan. For P-256 and P-384 the scalar is first made odd (an even k becomes n - k and the result is negated by mask), so every window adds a point and the sum is never infinity. The edwards25519 sum starts as the neutral element scaled by a random factor.
- **ECDSA nonce inversion** is blinded: k^-1 = b·(k·b)^-1 for a random b, so the inversion never runs on the nonce itself.
- **Data Independent Timing:** on Apple M4, an X25519 multiplication by a scalar with few set bits ran measurably faster than by a random scalar (|t| up to 25), though the compiled ladder has no branch or index on the scalar. Arm allows that unless the processor's DIT mode is on. Every operation on a private key (and RSA's private operation) now runs inside `DataIndependentTiming.run`, which turns the mode on where the processor has it and leaves it on for the thread (turning it off after each call cost about 17 ns on M4, and code measured no slower with it on); with it on, every case is clean. The timing spec measures with the mode on, as the library runs: with it off, M4 also multiplied the P-256 generator by 1 faster than by random scalars (|t| = 21), its running sum sitting at infinity (Z = 0) for most windows.
- **No arithmetic on the point at infinity** (P-256 and P-384): the generator multiplication never reaches infinity (odd digits, above). The variable-point multiplication keeps, while its running sum is still infinity, a stand-in [2^e]P that is doubled with the sum, so it changes every window, and a bit that says so; a digit 0 reads a real multiple, a different one each window, and the sum is dropped by mask. Before, the sum sat at Z = 0 and each zero digit read an all-zero table entry, and AMD Zen 3 and Zen 4 ran a scalar with zero windows measurably faster ([Timing on x86-64](#timing-on-x86-64)). Specs check the odd digits against the scalar and the stand-in against every digit, and compare sparse scalars with the variable-time multiplication.
- **Verification is variable time on purpose:** its inputs are public.

### How it is tested

#### Published vectors: 2,957 cases

| Algorithm | NIST CAVP | RFC | Wycheproof | Total |
|---|---|---|---|---|
| X25519 | | 5 | 518 | 523 |
| Ed25519 | | 5 | 210 | 215 |
| P-256 ECDH | | | 355 | 355 |
| P-256 ECDSA | 157 | 10 | 746 | 913 |
| P-384 ECDSA | 157 | 10 | 784 | 951 |

The slow suite (`--tag slow`) also runs the RFC 7748 iteration to 1,000,000 steps. Every Wycheproof `valid` case is accepted and every `invalid` case refused; `acceptable` cases are printed with the decision taken. Two Wycheproof files (`x25519_test.json`, `ecdh_secp256r1_ecpoint_test.json`) carry private-key fields that match the commit secret scan, so they are not committed; `scripts/fetch_vectors.rb --missing` installs them and checks their sha256.

#### Differential against OpenSSL

`spec/differential/libcrypto_curve_differential_spec.cr`, against OpenSSL 4.1.0 on the build Mac and against the runner's OpenSSL on every pull request (x86-64 and AArch64):

| Algorithm | Cases | Altered cases | Mismatches |
|---|---|---|---|
| X25519 | 1,000,000 (public key and shared secret each) | | 0 |
| Ed25519 | 200,000 (key, signature, verdict) | 200,000 | 0 |
| P-256 ECDH | 200,000 | altered points | 0 |
| P-256 ECDSA | 200,000 (each side verifies the other) | 200,000 | 0 |
| P-384 ECDSA | 200,000 | 200,000 | 0 |
| Wycheproof, X25519 and Ed25519 | every case | | same verdict as OpenSSL |

#### Constant time, three methods

- **Timing** (`spec/constant_time/public_key_timing_spec.cr`, dudect method, |t| below 4.5): X25519 multiplication and public key, Ed25519 key derivation and signing, P-256 generator and shared-secret multiplication, signing and the RFC 6979 nonce, each under a fixed secret (all zero, or 1) against random secrets. 1,000,000 measurements per class on the build Mac; CI runs 100,000, pinned to one core, and logs the processor. Each check is decided by two runs out of three, each a fresh measurement: two runs under 4.5 pass, two at 4.5 or more are a leak.
- **Memory checker** (`spec/probes/secret_taint.cr` under Valgrind): the keys, seeds and scalars are undefined memory; Memcheck reports any branch or address computed from them. The points where a verdict or a signature is meant to become public tell Memcheck so.
- **Compiled code** (`scripts/check_secret_flow.rb` on the optimized LLVM IR): secrets passed by value (limbs, points) are followed as well as those in buffers; a planted table lookup indexed by a limb must be reported.

#### Timing on x86-64

After the x86-64 P-256 multiplication moved into assembly (#13), the x86-64 timing check failed on some CI runs and passed on others with the same code: P-256 generator multiplication by 1, |t| = 15.28; signing with the nonce 1, 13.72; ECDH under the key 1, 9.2 and 15.63; X25519 with the all-zero scalar, 4.54. Investigated on 2026-11-24 on GitHub's ubuntu-24.04 runners; the probes, the workflow and every run are on the `x86-timing-investigation` branch.

- **It follows the processor.** CI's timing step, repeated six times on each of 20 runners at CI's 100,000 measurements per class: the 18 runners on Intel Xeon 6975P-C (Granite Rapids) and AMD EPYC 9V45 (Zen 5) stayed under 4.5 in every P-256 case; the two on AMD EPYC 9V74 (Zen 4, family 25 model 17) failed 33 of the 36 P-256 cases (|t| 4.4 to 27.3). AMD EPYC 7763 (Zen 3) runners, measured later, show the same effect. Across every later run, Intel runners (Xeon 6975P-C, Platinum 8573C and 8370C) and Zen 5 stayed under 4.5.
- **It is in the operand values, not in the code path.** The x86-64 machine code of the curve functions has no conditional branch except loop counters and public bit positions, and no division (`objdump` of the release build); Valgrind's taint check runs the x86-64 machine code and reports 0 errors on the P-256 and X25519 operations. At 1,000,000 measurements per class, 64 chained field multiplications by zero ran no faster than by random values on any processor, so the multiplier itself is not it.
- **Both field implementations show it, so the assembly is not the cause.** On Zen 3 and Zen 4, scalar 1 against random scalars, 1,000,000 measurements per class: the generator multiplication gave |t| up to 99 with the assembly and up to 244 with fiat-crypto's code alone (`-Dberyl_portable_curves`); ECDH under the key 1 up to 78 and 63.
- **The cause:** structured operands. With the scalar 1, the running sum sat at infinity (Z = 0) for 51 of 52 windows and each zero digit read an all-zero table entry, so most of the arithmetic ran on zeros; once that was removed, operands that stayed the same from one window to the next (a stand-in put back each window, the sum unchanged across zero digits) still ran faster. Apple M4 with Data Independent Timing off showed the same kind of effect (|t| = 21), and x86-64 gives programs no such mode.
- **The fix** gives every window fresh operands: odd digits for the generator multiplication, an evolving stand-in and a different dummy multiple per zero digit for the variable-point one, a randomized starting point for the X25519 ladder and the edwards25519 base-point multiplication, and a blinded nonce inversion. At 1,000,000 measurements per class (main, then the fix):

| Case | AMD EPYC 9V74 (Zen 4) | AMD EPYC 7763 (Zen 3) |
|---|---|---|
| P-256 generator × 1 | 10.6 to 58.6 → 2.2 to 4.1 | up to 59.8 (4 runs of 10 above 4.5) → 1.1 to 2.8 in 7 runs of 10, 4.5 to 15.3 in 3 |
| P-256 ECDH, key 1 | 16.1 to 51.1 → 1.7 to 3.8 | 15.8 to 44.9 → 1.6 to 3.5 |
| X25519, a fixed scalar | up to 17.4 → 1.2 to 2.6 | up to 6.4 → 1.3 to 2.8 |

- **What is left is the host, not the code.** On some Zen 3 hosts, every fixed input runs at a measurably different speed from random inputs, whatever the code: ChaCha20 with the all-zero key, which is only additions, rotations and XORs, gave |t| of 4.5 to 19.8 in 6 runs of 10 across five hosts, and a fixed *random* P-256 scalar gave 7.3 to 9.7 on the host where the scalar 1 reached 15.3 (and 8.3 on another), against 1.7 to 3.9 in the other runs. That matches data-dependent power and frequency on these processors (the "Hertzbleed" class, CVE-2022-23823 for AMD), which no change to Beryl's code removes. Intel and Zen 5 hosts stayed clean throughout.
- **CI's step on the final code**, on 10 AMD runners (6 Zen 3, 3 Zen 4, 1 Zen 5), 28 checks each: none failed. Every curve case stayed at or under 4.15 in every run; ChaCha20's all-zero key reached 7.12 in one run on a Zen 3 host and was outvoted by the other two. A Zen 3 host that disturbs two runs of three can still fail a check, and the log then names its processor.
- **The gate:** the threshold stays 4.5. Each check now takes two runs out of three, the timing runs pinned to one core, and both timing jobs log `lscpu` and the microcode, so a failure names the processor it ran on. The harness also recorded nothing for its uncut statistic until now: `tap` on a struct added each measurement to a copy (fixed in `spec/support/timing_leak_measurement.cr`).

### Speed

`bench/public_key_against_libcrypto.cr` against OpenSSL (the bench prints its version as 4.0.1), on m4-mini-01 (Apple M4, 4 performance and 6 efficiency cores) with all ten cores reserved for the run: ten rounds of 2 s of processor time per arm, the arms taking turns of 5 ms and counting thread processor time, so both see the same load. Milestone F3b, commit e7a0765, Data Independent Timing on (`bench-public-key-main-vs-f3b-curves-e7a0765-m4-mini-01-10-cores.txt` in the F3b evidence also has main measured in the same session).

| Algorithm | Operation | Beryl operations/s (median) | libcrypto operations/s (median) | Beryl against libcrypto (median of rounds) | Paired 95% interval | At least as fast |
|---|---|---|---|---|---|---|
| X25519 | key generation | 75893 | 62540 | 1.21× as fast | 1.21× as fast to 1.22× as fast | yes |
| X25519 | shared secret | 56166 | 54342 | 1.034× as fast | 1.033× as fast to 1.035× as fast | yes |
| Ed25519 | key generation | 75239 | 61348 | 1.23× as fast | 1.23× as fast to 1.23× as fast | yes |
| Ed25519 | sign | 71482 | 62097 | 1.15× as fast | 1.15× as fast to 1.15× as fast | yes |
| Ed25519 | verify | 33555 | 25050 | 1.34× as fast | 1.34× as fast to 1.34× as fast | yes |
| P-256 | key generation | 198511 | 132875 | 1.49× as fast | 1.49× as fast to 1.5× as fast | yes |
| P-256 ECDSA | sign | 115867 | 90104 | 1.28× as fast | 1.28× as fast to 1.29× as fast | yes |
| P-256 ECDSA | verify | 39759 | 30647 | 1.3× as fast | 1.3× as fast to 1.3× as fast | yes |
| P-256 ECDH | shared secret | 43240 | 40957 | 1.056× as fast | 1.056× as fast to 1.057× as fast | yes |
| P-384 ECDSA | verify | 7224 | 4813 | 1.5× as fast | 1.5× as fast to 1.5× as fast | yes |

Before milestone F3, P-256 ran 2.5 to 3 times slower and P-384 verification 1.35 times slower. F3 put the field in assembly and moved to Jacobian coordinates and Booth windows, which left P-256 signing (1.074 times slower), ECDH (1.1 times slower) and X25519 key agreement (1.013 times slower) behind OpenSSL. Milestone F3b closed those gaps: inversion by divsteps (signing went from 1.087 times slower to 1.28 times as fast, measured in the same run against main), the P-256 field code written for the flag-limited M4 (point doubling 59 to 52 ns), table selection on the vector registers, and ECDH computing only x. Every row is now at least as fast as OpenSSL.

## RSA

`Beryl::Crypto::V1::RivestShamirAdleman` (`RSA` for short) implements RFC 8017: PKCS #1 v1.5 signatures (§8.2), PSS signatures (§8.1) and OAEP encryption (§7.1). TLS and certificates need the signatures; MySQL's `caching_sha2_password` encrypts the password with OAEP over SHA-1.

```crystal
require "beryl"

alias RSA = Beryl::Crypto::V1::RSA
alias SHA256 = Beryl::Crypto::V1::SHA256

# A public key from its modulus (big-endian bytes) and public exponent.
public_key = RSA::PublicKey.new(modulus, 65_537)
public_key.verify_pkcs1_signature(message, signature, hash_function: SHA256)                # => true or false
public_key.verify_pss_signature(message, signature, hash_function: SHA256, salt_bytesize: 32) # => true or false
ciphertext = public_key.encrypt_with_oaep("password", hash_function: Beryl::Crypto::Compatibility::SHA1)

# A private key from the eight components of RFC 8017 §3.2.
private_key = RSA::PrivateKey.new(
  modulus: n, public_exponent: e, private_exponent: d,
  first_prime: p, second_prime: q,
  first_prime_exponent: d_p, second_prime_exponent: d_q, coefficient: q_inv,
)
private_key.sign_with_pkcs1(message, hash_function: SHA256)
private_key.sign_with_pss(message, hash_function: SHA256, salt_bytesize: 32)
private_key.decrypt_with_oaep(ciphertext, hash_function: Beryl::Crypto::Compatibility::SHA1) # => Bytes or nil
```

| Call | Hashes it takes | On bad input |
|---|---|---|
| `PrivateKey#sign_with_pkcs1` | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256 | — |
| `PublicKey#verify_pkcs1_signature` | the same, and `Compatibility::SHA1` | `false` |
| `PrivateKey#sign_with_pss` | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256, the same hash for MGF1 | `SaltTooLongForModulus` |
| `PublicKey#verify_pss_signature` | the same | `false` |
| `PublicKey#encrypt_with_oaep` | `Compatibility::SHA1` and the SHA-2 hashes above, the same hash for MGF1 | `MessageTooLongForModulus` |
| `PrivateKey#decrypt_with_oaep` | the same | `nil` |

A hash outside a scheme's list is a compile-time error. Verification never raises for a malformed signature, and decryption gives the same `nil` for every malformed ciphertext.

**Keys.** A public key takes a modulus of 2,048 to 8,192 bits; a private key, 2,048 to 4,096 bits with two primes. The public exponent is odd, from 3 to 2^32 - 1. Anything else raises `KeySizeNotSupported` or `PublicExponentNotSupported`. A private key is checked when it is built, in constant time and as one verdict: both primes odd and of about half the modulus size, their product the modulus, each exponent and the coefficient below its prime, the coefficient the inverse of q modulo p, d below the modulus; then one private operation is run and checked with the public exponent. A failure raises `MalformedPrivateKey`. Key generation and keys of three or more primes are not supported; keys come from key files, which Mica parses (milestone B4). `PrivateKey#wipe` (also run by the finalizer) overwrites the key's secret parts.

### How the code avoids leaking secrets

The arithmetic (`MontgomeryArithmetic`) follows BearSSL's `i31` and `i62` code on 64-bit words, with each word product a `UInt128`:

- Montgomery multiplication by finely integrated operand scanning (one pass per word adds both products), with one subtraction of the modulus at the end, kept or dropped by mask. A copy is compiled for 16, 24, 32, 48 and 64 words (the primes and moduli of 2,048, 3,072 and 4,096-bit keys), so the loops have a constant length. On AArch64 (milestone F3) those copies are inline assembly (`MontgomeryMultiplicationInAssembly`): for 16 words the running sum stays in registers and the carries in the carry flag, with a separate squaring that forms each cross product once; for more words the sum is in memory. Each has one loop at most, over the words of b, whose count is the word count, and no address computed from data. A Montgomery product below the modulus has one value, so the assembly returns exactly what the Crystal code returns; `spec/beryl/crypto/v1/montgomery_arithmetic_spec.cr` compares the two, and `-Dberyl_portable_rsa` builds the Crystal code alone.
- On x86-64 (P1 fix) the same copies are inline assembly chosen at run time. Where the processor has BMI2 and ADX (`ProcessorFeatures::HAS_WIDE_MULTIPLY_WITH_TWO_CARRY_CHAINS`), `MontgomeryMultiplicationWithTwoCarryChains` runs the AArch64 kernel's strips of eight words with `mulx`, the low halves of each row of word products going up the carry flag with `adcx` and the high halves up the overflow flag with `adox` (Ozturk, Guilford, Gopal and Feghali, Intel, 2012), and squares forming each cross product once. Where it also has AVX-512 IFMA (`HAS_AVX512_INTEGER_FUSED_MULTIPLY_ADD`), `MontgomeryMultiplicationWithIntegerFusedMultiplyAdd` runs the private operation's two exponentiations side by side in radix 2^52 (almost Montgomery multiplication after Gueron, in the arrangement of OpenSSL's `rsaz-avx512` on 512-bit registers, two independent multiplications per statement, the table entry kept by a masked blend after every entry is read), for primes of 16, 24 or 32 words of the same size, and the public operation one multiplication at a time for moduli of 32, 48 or 64 words. `-Dberyl_without_avx512` and `-Dberyl_without_mulx` take the narrower paths, and the spec compares every path with the Crystal code (the IFMA exponentiations with the 64-bit ones). Valgrind's processor has no AVX-512, so its taint check covers the MULX path; the timing check and the differential cover whichever path the runner takes.
- R² mod m without division: 1 doubled modulo m 65n times, then six Montgomery squarings. The low-word inverse by Newton's iteration.
- Exponentiation with a fixed window of 4 bits: the same squarings and one multiplication per window, the table entry chosen by reading every entry and keeping one by mask.
- The private operation by the Chinese remainder theorem, after BearSSL's `rsa_i31_priv.c`: the input is reduced into each prime's Montgomery form chunk by chunk (Horner's rule with R²), raised to d_p and d_q, and joined with Garner's formula. The result is raised to the public exponent and compared with the input before it is released; a mismatch (a fault in the computation) raises `FaultInPrivateKeyOperation`, as OpenSSL and BoringSSL check.
- OAEP decoding after BearSSL's `rsa_oaep_unpad.c`: every byte is read, every check folds into one verdict by mask, and the verdict (with the message length) passes once through `Declassification.reveal`. A ciphertext at or above the modulus folds into the same verdict.

Public-key operations (verification, encryption) work on public values only and may take time that depends on them.

Two kinds of value pass through `Declassification.reveal` besides verdicts: the size and low bit of a modulus and the value of the public exponent, which are public but read from a byte buffer; and the bit length of each prime, which sets the word count the arithmetic works in, as BearSSL also allows.

### How it is tested

(The counts below come from the runs recorded in the pull request.)

#### Published vectors

`crystal-alpha spec` prints the table after the suite.

| Scheme | CAVP | Wycheproof |
|---|---|---|
| PKCS #1 v1.5 verify | 216 | 4,137 |
| PKCS #1 v1.5 sign | 100 | 93 |
| PSS verify | 180 | 1,204 |
| PSS sign | 100 | — |
| OAEP decrypt | — | 417 |

Wycheproof cases marked `acceptable`, and how Beryl decides them:

- `rsa_signature_*` tcId 8, "Missing NULL in the ASN encoding": refused. Beryl compares the whole encoding with the one DigestInfo RFC 8017 §9.2 defines.
- `rsa_pkcs1_2048_sig_gen_test.json` SHA-1 group (tcId 65 to 72): Beryl signs with SHA-2 only; the published signatures verify.
- `rsa_pkcs1_{2048,3072}_sig_gen_test.json` "SmallPublicKey" groups (tcId 154, 155, 158, 156, 157): the key's primes differ in size by about a third of the modulus; `PrivateKey` refuses such a key, and the published signatures verify.
- `rsa_oaep_misc_test.json` tcId 376, 385, 392, "em represents a small integer": accepted.

The 1,024 and 1,536-bit sections and the three-prime OAEP files are below the key policy or outside two-prime keys. The files and parts left out, and why:

| Source | Left out | Why |
|---|---|---|
| CAVP `SigVer15_186-3.rsp`, `SigVerPSS_186-3.rsp`, and their `_TruncatedSHAs` files | the 1,024-bit sections | below the 2,048-bit minimum |
| CAVP `*_TruncatedSHAs` files | SHA-512/224 cases | SHA-512/224 is not implemented |
| CAVP `SigVerPSS_186-3.rsp` | SHA-1 cases | PSS takes SHA-2 only |
| CAVP `SigGen931*`, `SigVer931*`, `KeyGen*` | all | ANSI X9.31 signatures and key generation are not implemented |
| Wycheproof `rsa_signature_*_sha3_*`, `rsa_signature_2048_sha512_224_test.json` | all | SHA-3 and SHA-512/224 are not implemented |
| Wycheproof `rsa_pkcs1_{1024,1536}_sig_gen_test.json` | all | below the 2,048-bit minimum |
| Wycheproof `rsa_pkcs1_{2048,3072,4096}_test.json` | all | PKCS #1 v1.5 encryption is not implemented |
| Wycheproof `rsa_pss_*_shake*`, `rsa_pss_2048_sha512_224_mgf1_28_test.json` | all | SHAKE and SHA-512/224 are not implemented |
| Wycheproof `rsa_pss_2048_sha1_mgf1_20_test.json` | all | PSS takes SHA-2 only |
| Wycheproof `rsa_pss_2048_sha256_mgf1sha1_20_test.json` | all | MGF1 with a different hash than the message |
| Wycheproof `rsa_pss_*_params_test.json` | all | the key is given as DER with PSS parameters, which Mica parses (B4) |
| Wycheproof `rsa_pss_misc_test.json` | 126 of 150 cases | SHA-1, or MGF1 with a different hash |
| Wycheproof `rsa_oaep_*_mgf1sha1_test.json` where the message hash is not SHA-1 | all | MGF1 with a different hash than the message |
| Wycheproof `rsa_oaep_2048_sha512_224_*` | all | SHA-512/224 is not implemented |
| Wycheproof `rsa_oaep_misc_test.json` | 333 of 395 cases | MGF1 with a different hash, or a modulus outside 2,048 to 4,096 bits |
| Wycheproof `rsa_three_primes_oaep_*` | all | keys of three primes are not supported |

The Wycheproof files that carry private keys (`rsa_oaep_*`, `rsa_pkcs1_*_sig_gen_test.json`) match the commit secret scan, so they are kept out of git: `.gitignore` lists them, `spec/vectors/manifest.json` pins each by sha256, and `/usr/bin/ruby scripts/fetch_vectors.rb --missing` installs them (CI runs it before the specs).

#### Differential against OpenSSL

`spec/differential/libcrypto_rsa_differential_spec.cr`: libcrypto makes a pool of keys, Beryl builds the same keys from their components, and every case draws a hash, a message and a salt size or a label from the seeded generator. PKCS #1 v1.5 signatures must be equal byte for byte; PSS signatures and OAEP ciphertexts must be accepted by the other side; and a mutated signature, message, ciphertext or label (one bit flipped, or a value at or above the modulus) must get the same verdict from both. 20,000, 5,000 and 2,000 cases per scheme at 2,048, 3,072 and 4,096 bits, one process each. CI runs it on x86-64 and AArch64 Linux against the system OpenSSL 3.

#### Constant time, three methods

- Timing (`spec/constant_time/rsa_timing_spec.cr`, dudect's method): the private operation at 2,048, 3,072 and 4,096 bits on a fixed input against random inputs, OAEP decoding of well-formed encodings against encodings broken at any place, and of encodings broken at the first byte against ones broken before the separator; |t| < 4.5. A planted early exit in OAEP decoding is reported. 200,000 measurements per class on the build Mac for each pull request, 50,000 in CI.
- Memory checker (`spec/probes/secret_taint.cr`, Linux CI): the Chinese remainder exponentiation with primes, exponents, coefficient, modulus and input all undefined to Memcheck at 2,048, 3,072 and 4,096 bits, the component check, and OAEP decoding under SHA-1 and SHA-256.
- Compiled code (`spec/probes/secret_flow.cr`, `scripts/check_secret_flow.rb`): key construction, PKCS #1 v1.5 and PSS signing, and OAEP decryption. `MontgomeryArithmetic` is a secret-buffer module and the RSA key types are cipher objects to the checker. A planted table lookup indexed by an exponent byte (`leaky_table_selection`) is reported.

### Speed

`bench/rsa_against_libcrypto.cr` measures operations per second for PKCS #1 v1.5 and PSS signing and verification and OAEP encryption and decryption at 2,048, 3,072 and 4,096 bits, against OpenSSL (version 4.0.1 as the bench prints it), in the same way as the cipher bench. On m4-mini-01 (Apple M4, 4 performance and 6 efficiency cores) with all ten cores reserved for the run, milestone F3b commit 05d1481, ten rounds of 2 s per arm:

| Key | Operation | Beryl operations/s (median) | libcrypto operations/s (median) | Beryl against libcrypto (median of rounds) | Paired 95% interval | At least as fast |
|---|---|---|---|---|---|---|
| RSA-2048 | PKCS#1 v1.5 sign | 3369.2 | 3027.3 | 1.11× as fast | 1.11× as fast to 1.11× as fast | yes |
| RSA-2048 | PSS sign | 3362.7 | 3013.2 | 1.12× as fast | 1.12× as fast to 1.12× as fast | yes |
| RSA-2048 | PKCS#1 v1.5 verify | 137130.7 | 117021.5 | 1.17× as fast | 1.17× as fast to 1.17× as fast | yes |
| RSA-2048 | PSS verify | 128121.5 | 110980.8 | 1.15× as fast | 1.15× as fast to 1.16× as fast | yes |
| RSA-2048 | OAEP encrypt | 125550.1 | 110344.9 | 1.14× as fast | 1.14× as fast to 1.14× as fast | yes |
| RSA-2048 | OAEP decrypt | 3350.0 | 2996.9 | 1.12× as fast | 1.12× as fast to 1.12× as fast | yes |
| RSA-3072 | PKCS#1 v1.5 sign | 1138.2 | 1042.4 | 1.092× as fast | 1.092× as fast to 1.093× as fast | yes |
| RSA-3072 | PSS sign | 1136.6 | 1040.9 | 1.091× as fast | 1.09× as fast to 1.092× as fast | yes |
| RSA-3072 | PKCS#1 v1.5 verify | 67290.0 | 56031.8 | 1.2× as fast | 1.2× as fast to 1.2× as fast | yes |
| RSA-3072 | PSS verify | 63889.4 | 53915.1 | 1.19× as fast | 1.18× as fast to 1.19× as fast | yes |
| RSA-3072 | OAEP encrypt | 63485.6 | 53797.6 | 1.18× as fast | 1.18× as fast to 1.18× as fast | yes |
| RSA-3072 | OAEP decrypt | 1135.9 | 1039.4 | 1.093× as fast | 1.093× as fast to 1.093× as fast | yes |
| RSA-4096 | PKCS#1 v1.5 sign | 519.4 | 477.5 | 1.087× as fast | 1.087× as fast to 1.088× as fast | yes |
| RSA-4096 | PSS sign | 518.9 | 477.3 | 1.087× as fast | 1.087× as fast to 1.088× as fast | yes |
| RSA-4096 | PKCS#1 v1.5 verify | 39669.6 | 32827.3 | 1.21× as fast | 1.21× as fast to 1.21× as fast | yes |
| RSA-4096 | PSS verify | 37927.3 | 31871.7 | 1.19× as fast | 1.19× as fast to 1.19× as fast | yes |
| RSA-4096 | OAEP encrypt | 37622.4 | 31769.9 | 1.18× as fast | 1.18× as fast to 1.19× as fast | yes |
| RSA-4096 | OAEP decrypt | 518.8 | 476.9 | 1.088× as fast | 1.087× as fast to 1.088× as fast | yes |

Milestone F3 moved RSA's Montgomery multiplication, squaring and table selection into AArch64 assembly. RSA-2048 private operations (signing, OAEP decryption) are now 1.07 to 1.08 times as fast as OpenSSL, up from 1.7 times slower. Public operations at 2,048 bits are 1.5 times slower (from 1.95), and every operation at 3,072 and 4,096 bits is 1.5 to 1.63 times slower (from 2.0 to 2.2). The private operation runs under Data Independent Timing and checks its result with the public exponent before releasing it.

Milestone F3b replaced the 24- to 64-word Montgomery kernels with register strips (eight words of one factor held in registers against a streamed word of the other, two carry chains per row), added a squaring that forms each cross product once, widened the exponent window to five bits, and starts the public operation from R^e mod n so it saves the conversion product. Every RSA operation is now at least as fast as OpenSSL 4.0.1: private operations 1.087 to 1.12 times as fast, public operations 1.14 to 1.21 times as fast. `RSA::PublicKey` builds its Montgomery constants (R² mod n from the public modulus alone) on its first operation, so reading a key costs only decoding.
