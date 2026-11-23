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
- **Field arithmetic in assembly** (milestone F3): on AArch64 the P-256 field (multiplication, squaring, addition, subtraction, negation), the P-256 group order and the P-384 field and order (multiplication and squaring) run in inline assembly written out by macros in `src/beryl/crypto/field_arithmetic/fields_in_assembly.cr`; other processors, x86-64 among them, run fiat-crypto's code. (An x86-64 P-256 multiplication was tried and taken out: it matched fiat-crypto on its own, but ECDH built with `--release` gave wrong shared secrets in CI.) Montgomery multiplication word by word has one result for every input, so the assembly must return fiat-crypto's output bit for bit, and the equality program checks that it does on the same 100,000,000 inputs per function (CI runs 1,000,000). The assembly has no branch and no address computed from data; `-Dberyl_portable_curves` builds fiat-crypto's code alone, and CI runs the suite both ways. Apple M4 runs about three flag-setting instructions per cycle against two multiplications, and the curve code is limited by the flags, so the P-256 code spends them sparingly (milestone F3b): the Montgomery reduction forms w·(2^64 − 2^32 + 1) with `mul` and `umulh`, the squaring doubles its cross products with `extr`, and a field halving (`half`, a/2 mod p in five flag-setting instructions) lets the point doubling follow OpenSSL's `ecp_nistz256_point_double` with 10 additions and one halving instead of 14 additions. `half` has no fiat-crypto counterpart; the equality program checks that fiat-crypto's C `add` gives back a from half(a) + half(a), for inputs below p (the only ones the curve code passes), and that the assembly equals the portable Crystal halving bit for bit.
- **Inversion** on P-256 (modulo p and modulo the group order) and modulo 2^255 − 19 uses the divsteps of Bernstein and Yang, as libsecp256k1's constant-time `secp256k1_modinv64` writes them (`src/beryl/crypto/field_arithmetic/divstep_inversion.cr`): ten rounds of 59 divsteps, enough for any 256-bit input, each decision a mask. It takes about 1.1 µs on M4 where Fermat's exponentiation took 1.8 to 3.6 µs; a spec compares the two on 20,000 random values and the edge values per modulus. P-384 keeps Fermat.
- **X25519** is the Montgomery ladder of RFC 7748 with a masked swap. Public keys come from the edwards25519 tables below, mapped by u = (Z + Y) / (Z - Y), which equals the ladder on u = 9.
- **Ed25519** uses the complete addition formulas of RFC 8032, so no input takes a special branch; a secret scalar is processed four bits at a time and every table lookup reads all 16 entries.
- **P-256 and P-384** use Jacobian coordinates (dbl-2001-b and add-1998-cmo-2 for a = -3), with infinity handled by masks. Those formulas are wrong only when both operands are the same point, and each constant-time caller shows that it never adds a point to itself: a secret scalar is written in signed 5-bit windows (Booth's recoding, as in OpenSSL's nistz256), and before window i is added the running sum is [32·H]P with 0 < 32·H − d < n, so the operands differ. Every table lookup reads all 16 entries; on AArch64 it does so on the vector registers, merging each entry under a mask with `bit`.
- **Fixed-base multiplication** ([k]G, [k]B) uses one precomputed table per window (4 bits for edwards25519, signed 5 bits for P-256 and P-384, affine points), so it needs no doubling between windows, with the same full scan.
- **Data Independent Timing:** on Apple M4, an X25519 multiplication by a scalar with few set bits ran measurably faster than by a random scalar (|t| up to 25), though the compiled ladder has no branch or index on the scalar. Arm allows that unless the processor's DIT mode is on. Every operation on a private key (and RSA's private operation) now runs inside `DataIndependentTiming.run`, which turns the mode on where the processor has it and leaves it on for the thread (turning it off after each call cost about 17 ns on M4, and code measured no slower with it on); with it on, every case is clean. The timing spec measures with the mode on, as the library runs: with it off, M4 also multiplied the P-256 generator by 1 faster than by random scalars (|t| = 21), its running sum sitting at infinity (Z = 0) for most windows.
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

- **Timing** (`spec/constant_time/public_key_timing_spec.cr`, dudect method, |t| below 4.5): X25519 multiplication and public key, Ed25519 key derivation and signing, P-256 generator and shared-secret multiplication, signing and the RFC 6979 nonce, each under a fixed secret (all zero, or 1) against random secrets. 1,000,000 measurements per class on the build Mac; CI runs 100,000.
- **Memory checker** (`spec/probes/secret_taint.cr` under Valgrind): the keys, seeds and scalars are undefined memory; Memcheck reports any branch or address computed from them. The points where a verdict or a signature is meant to become public tell Memcheck so.
- **Compiled code** (`scripts/check_secret_flow.rb` on the optimized LLVM IR): secrets passed by value (limbs, points) are followed as well as those in buffers; a planted table lookup indexed by a limb must be reported.

### Speed

`bench/public_key_against_libcrypto.cr` against OpenSSL (the bench prints its version as 4.0.1), on m4-mini-01 (Apple M4, 4 performance and 6 efficiency cores) with all ten cores reserved for the run: ten rounds of 2 s of processor time per arm, the arms taking turns of 5 ms and counting thread processor time, so both see the same load. Milestone F3, commit b3c72ee, Data Independent Timing on.

| Algorithm | Operation | Beryl operations/s (median) | libcrypto operations/s (median) | Beryl against libcrypto (median of rounds) | Paired 95% interval | At least as fast |
|---|---|---|---|---|---|---|
| X25519 | key generation | 72159 | 62854 | 1.15× as fast | 1.15× as fast to 1.15× as fast | yes |
| X25519 | shared secret | 54439 | 55109 | 1.013× slower | 1.014× slower to 1.012× slower | no |
| Ed25519 | key generation | 71756 | 61908 | 1.16× as fast | 1.16× as fast to 1.16× as fast | yes |
| Ed25519 | sign | 67827 | 62245 | 1.088× as fast | 1.085× as fast to 1.091× as fast | yes |
| Ed25519 | verify | 34522 | 24954 | 1.38× as fast | 1.38× as fast to 1.38× as fast | yes |
| P-256 | key generation | 189622 | 132884 | 1.43× as fast | 1.42× as fast to 1.43× as fast | yes |
| P-256 ECDSA | sign | 83198 | 89264 | 1.074× slower | 1.074× slower to 1.072× slower | no |
| P-256 ECDSA | verify | 33757 | 30808 | 1.096× as fast | 1.095× as fast to 1.097× as fast | yes |
| P-256 ECDH | shared secret | 37323 | 41159 | 1.1× slower | 1.1× slower to 1.1× slower | no |
| P-384 ECDSA | verify | 6856 | 4870 | 1.41× as fast | 1.41× as fast to 1.41× as fast | yes |

Before milestone F3, P-256 ran 2.5 to 3 times slower and P-384 verification 1.35 times slower. With the field in assembly, Jacobian coordinates and Booth windows, P-256 key generation is now 1.43 times as fast as OpenSSL, ECDSA verification 1.096 times as fast and P-384 verification 1.41 times as fast. P-256 signing (1.074 times slower) and ECDH (1.1 times slower) are still behind OpenSSL's nistz256 assembly, as is X25519 key agreement (1.013 times slower). Ed25519 and X25519 key generation and Ed25519 signing and verification are faster than OpenSSL.

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

- Timing (`spec/constant_time/rsa_timing_spec.cr`, dudect's method): the private operation on a fixed input against random inputs, OAEP decoding of well-formed encodings against encodings broken at any place, and of encodings broken at the first byte against ones broken before the separator; |t| < 4.5. A planted early exit in OAEP decoding is reported. 200,000 measurements per class on the build Mac for each pull request, 50,000 in CI.
- Memory checker (`spec/probes/secret_taint.cr`, Linux CI): the Chinese remainder exponentiation with primes, exponents, coefficient, modulus and input all undefined to Memcheck at 2,048, 3,072 and 4,096 bits, the component check, and OAEP decoding under SHA-1 and SHA-256.
- Compiled code (`spec/probes/secret_flow.cr`, `scripts/check_secret_flow.rb`): key construction, PKCS #1 v1.5 and PSS signing, and OAEP decryption. `MontgomeryArithmetic` is a secret-buffer module and the RSA key types are cipher objects to the checker. A planted table lookup indexed by an exponent byte (`leaky_table_selection`) is reported.

### Speed

`bench/rsa_against_libcrypto.cr` measures operations per second for PKCS #1 v1.5 and PSS signing and verification and OAEP encryption and decryption at 2,048, 3,072 and 4,096 bits, against OpenSSL (version 4.0.1 as the bench prints it), in the same way as the cipher bench. On m4-mini-01 (Apple M4, 4 performance and 6 efficiency cores) with all ten cores reserved for the run, milestone F3 commit b3c72ee, ten rounds of 2 s per arm:

| Key | Operation | Beryl operations/s (median) | libcrypto operations/s (median) | Beryl against libcrypto (median of rounds) | Paired 95% interval | At least as fast |
|---|---|---|---|---|---|---|
| RSA-2048 | PKCS#1 v1.5 sign | 3240.4 | 3032.4 | 1.069× as fast | 1.068× as fast to 1.069× as fast | yes |
| RSA-2048 | PSS sign | 3239.6 | 3018.9 | 1.073× as fast | 1.073× as fast to 1.074× as fast | yes |
| RSA-2048 | PKCS#1 v1.5 verify | 77418.2 | 116139.2 | 1.5× slower | 1.5× slower to 1.5× slower | no |
| RSA-2048 | PSS verify | 74343.5 | 110651.5 | 1.49× slower | 1.49× slower to 1.49× slower | no |
| RSA-2048 | OAEP encrypt | 73874.6 | 109943.9 | 1.49× slower | 1.49× slower to 1.49× slower | no |
| RSA-2048 | OAEP decrypt | 3239.4 | 3005.5 | 1.078× as fast | 1.077× as fast to 1.078× as fast | yes |
| RSA-3072 | PKCS#1 v1.5 sign | 686.5 | 1039.5 | 1.51× slower | 1.51× slower to 1.51× slower | no |
| RSA-3072 | PSS sign | 686.4 | 1039.1 | 1.51× slower | 1.51× slower to 1.51× slower | no |
| RSA-3072 | PKCS#1 v1.5 verify | 35212.5 | 55510.9 | 1.58× slower | 1.58× slower to 1.57× slower | no |
| RSA-3072 | PSS verify | 34326.9 | 53836.7 | 1.57× slower | 1.57× slower to 1.57× slower | no |
| RSA-3072 | OAEP encrypt | 34123.9 | 53587.1 | 1.57× slower | 1.57× slower to 1.57× slower | no |
| RSA-3072 | OAEP decrypt | 686.2 | 1037.2 | 1.51× slower | 1.51× slower to 1.51× slower | no |
| RSA-4096 | PKCS#1 v1.5 sign | 294.5 | 477.5 | 1.62× slower | 1.62× slower to 1.62× slower | no |
| RSA-4096 | PSS sign | 294.4 | 477.2 | 1.62× slower | 1.62× slower to 1.62× slower | no |
| RSA-4096 | PKCS#1 v1.5 verify | 20005.5 | 32529.6 | 1.63× slower | 1.63× slower to 1.63× slower | no |
| RSA-4096 | PSS verify | 19645.8 | 31611.8 | 1.61× slower | 1.61× slower to 1.61× slower | no |
| RSA-4096 | OAEP encrypt | 19578.3 | 31562.1 | 1.61× slower | 1.61× slower to 1.61× slower | no |
| RSA-4096 | OAEP decrypt | 294.4 | 476.5 | 1.62× slower | 1.62× slower to 1.62× slower | no |

Milestone F3 moved RSA's Montgomery multiplication, squaring and table selection into AArch64 assembly. RSA-2048 private operations (signing, OAEP decryption) are now 1.07 to 1.08 times as fast as OpenSSL, up from 1.7 times slower. Public operations at 2,048 bits are 1.5 times slower (from 1.95), and every operation at 3,072 and 4,096 bits is 1.5 to 1.63 times slower (from 2.0 to 2.2). The private operation runs under Data Independent Timing and checks its result with the public exponent before releasing it.
